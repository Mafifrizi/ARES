"""SQLite coverage for revision 0008 schema reconciliation."""
from __future__ import annotations

import asyncio
import importlib
import re
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from ares.db.database import AresDatabase

_ROOT = Path(__file__).resolve().parents[2]
_CATALOG_ERROR = "Incompatible catalog for migration 0008"
_DATA_ERROR = "Unsafe data for migration 0008"
_FORWARD_ONLY_ERROR = "Migration 0008 is forward-only"
_DIALECT_ERROR = "Unsupported migration dialect"


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


@contextmanager
def _database(label: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix=f"ares-0008-{label}-",
        ignore_cleanup_errors=True,
    ) as directory:
        yield Path(directory) / "migration.db"


def _config(path: Path) -> Config:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(_ROOT / "migrations"),
    )
    config.set_main_option(
        "sqlalchemy.url",
        f"sqlite:///{path.as_posix()}",
    )
    return config


def _upgrade(path: Path, revision: str) -> None:
    command.upgrade(_config(path), revision)


def _downgrade(path: Path, revision: str) -> None:
    command.downgrade(_config(path), revision)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _version(path: Path) -> str | None:
    with _connect(path) as connection:
        row = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    return None if row is None else str(row[0])


def _catalog(path: Path) -> tuple[tuple[object, ...], ...]:
    with _connect(path) as connection:
        return tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                  AND name != 'alembic_version'
                ORDER BY type, name
                """
            )
        )


def _data(path: Path) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
    with _connect(path) as connection:
        tables = tuple(
            str(row[0])
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                  AND name NOT LIKE 'sqlite_%'
                  AND name != 'alembic_version'
                ORDER BY name
                """
            )
        )
        return tuple(
            (
                table,
                tuple(
                    connection.execute(
                        f'SELECT * FROM "{table}" ORDER BY rowid'  # noqa: S608
                    )
                ),
            )
            for table in tables
        )


def _logical_data(path: Path) -> tuple[tuple[str, tuple[object, ...]], ...]:
    with _connect(path) as connection:
        tables = tuple(
            str(row[0])
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                  AND name NOT LIKE 'sqlite_%'
                  AND name != 'alembic_version'
                ORDER BY name
                """
            )
        )
        logical: list[tuple[str, tuple[object, ...]]] = []
        for table in tables:
            columns = tuple(
                str(row[1])
                for row in connection.execute(
                    f'PRAGMA table_info("{table}")'  # noqa: S608
                )
            )
            rows = tuple(
                sorted(
                    tuple(sorted(zip(columns, tuple(row), strict=True)))
                    for row in connection.execute(
                        f'SELECT * FROM "{table}"'  # noqa: S608
                    )
                )
            )
            logical.append((table, rows))
        return tuple(logical)


def _snapshot(path: Path) -> tuple[object, ...]:
    with _connect(path) as connection:
        sequence = tuple(
            connection.execute(
                "SELECT name, seq FROM sqlite_sequence ORDER BY name"
            )
        )
        foreign_keys = int(
            connection.execute("PRAGMA foreign_keys").fetchone()[0]
        )
    return (_version(path), _catalog(path), _data(path), sequence, foreign_keys)


def _physical_catalog_identity(path: Path) -> tuple[object, ...]:
    with _connect(path) as connection:
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        objects = tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, rootpage
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            )
        )
    return (schema_version, objects)


def _complete_managed_contract_is_exact(path: Path) -> bool:
    from tests.unit import test_migration_portability as portability
    from tests.unit import test_websocket_ticket_migration as ticket

    with _connect(path) as connection:
        actual = portability._sqlite_catalog_contract(connection)
    non_ticket = replace(
        actual,
        tables=tuple(
            table for table in actual.tables if table != "websocket_tickets"
        ),
        columns=tuple(
            item for item in actual.columns if item[0] != "websocket_tickets"
        ),
        primary_keys=tuple(
            item
            for item in actual.primary_keys
            if item[0] != "websocket_tickets"
        ),
        unique_constraints=tuple(
            item
            for item in actual.unique_constraints
            if item[0] != "websocket_tickets"
        ),
        checks=tuple(
            item for item in actual.checks if item[0] != "websocket_tickets"
        ),
        foreign_keys=tuple(
            item
            for item in actual.foreign_keys
            if item[0] != "websocket_tickets"
        ),
        indexes=tuple(
            item for item in actual.indexes if item[0] != "websocket_tickets"
        ),
    )
    return (
        non_ticket == portability._fixed_sqlite_contract("0006")
        and ticket._ticket_contract(path)
        == ticket._EXPECTED_TICKET_CONTRACT
    )


def _seed_graph(path: Path) -> None:
    with _connect(path) as connection:
        connection.execute(
            "INSERT INTO campaigns(id, name) VALUES('c1', 'campaign')"
        )
        connection.execute(
            """
            INSERT INTO hosts(id, campaign_id, ip_address)
            VALUES('h1', 'c1', '192.0.2.1')
            """
        )
        connection.execute(
            """
            INSERT INTO credentials(
                id, campaign_id, host_id, username, cred_type,
                cracked_value_enc
            ) VALUES('k1', 'c1', 'h1', 'alice', 'password', 'ciphertext')
            """
        )
        connection.execute(
            """
            INSERT INTO loot(id, campaign_id, host_id, loot_type, name)
            VALUES('l1', 'c1', 'h1', 'file', 'artifact')
            """
        )
        connection.execute(
            """
            INSERT INTO findings(
                id, campaign_id, module_id, title, description, severity,
                cvss_score, cvss_vector, trace_id
            ) VALUES(
                'f1', 'c1', 'm1', 'finding', 'description', 'high',
                8.1, 'vector', 'trace'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO users(id, username, hashed_password)
            VALUES('u1', 'alice', 'hash')
            """
        )
        connection.execute(
            """
            INSERT INTO api_keys(
                id, user_id, name, key_hash, key_prefix
            ) VALUES('a1', 'u1', 'key', 'hash', 'prefix')
            """
        )
        connection.execute(
            """
            INSERT INTO refresh_tokens(id, user_id, expires_at)
            VALUES('r1', 'u1', '2099-01-01 00:00:00')
            """
        )
        connection.execute(
            """
            INSERT INTO websocket_tickets(
                ticket_hash, campaign_id, user_id, credential_kind,
                api_key_id, required_scope, created_at, expires_at
            ) VALUES(
                ?, 'c1', 'u1', 'api_key', 'a1', 'read',
                '2098-01-01T00:00:00.000Z',
                '2098-01-01T00:01:00.000Z'
            )
            """,
            ("a" * 64,),
        )
        connection.execute(
            """
            INSERT INTO audit_log(campaign_id, action)
            VALUES('c1', 'seed')
            """
        )
        connection.commit()


def _attempt_upgrade(path: Path) -> str:
    try:
        _upgrade(path, "0008")
    except RuntimeError as exc:
        return str(exc)
    return ""


async def _runtime_bootstrap(path: Path) -> None:
    database = AresDatabase(f"file:{path.resolve().as_posix()}?mode=rwc")
    await database.connect()
    await database.close()


def _rewrite_table_sql(path: Path, table: str, old: str, new: str) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type='table' AND name=?
            """,
            (table,),
        ).fetchone()
        if row is None or not isinstance(row[0], str) or old not in row[0]:
            raise AssertionError("legacy fixture source fragment is absent")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=replace(sql, ?, ?)
            WHERE type='table' AND name=?
            """,
            (old, new, table),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _append_check_constraint(path: Path, table: str) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=substr(sql, 1, length(sql) - 1)
                    || ', CONSTRAINT unexpected_check CHECK (1))'
            WHERE type='table' AND name=?
            """,
            (table,),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _remove_users_unique_constraint(path: Path) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            """
            CREATE TABLE users_without_unique (
                id TEXT NOT NULL PRIMARY KEY,
                username TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT DEFAULT 'reporter' NOT NULL,
                is_active INTEGER DEFAULT '1' NOT NULL,
                created_by TEXT DEFAULT 'system' NOT NULL,
                created_at TEXT DEFAULT (datetime('now')) NOT NULL,
                last_login TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO users_without_unique
            SELECT * FROM users
            """
        )
        connection.execute("DROP TABLE users")
        connection.execute(
            "ALTER TABLE users_without_unique RENAME TO users"
        )
        connection.execute(
            "CREATE INDEX idx_users_username ON users(username)"
        )
        connection.execute("CREATE INDEX idx_users_role ON users(role)")
        connection.commit()


def _replace_users_unique_contract(path: Path, variant: str) -> None:
    unique_sql = {
        "duplicate": (
            "CONSTRAINT uq_users_username UNIQUE(username)"
        ),
        "nocase": (
            "CONSTRAINT uq_users_username "
            "UNIQUE(username COLLATE NOCASE)"
        ),
    }[variant]
    with _connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            f"""
            CREATE TABLE users_unique_variant (
                id TEXT NOT NULL PRIMARY KEY,
                username TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT DEFAULT 'reporter' NOT NULL,
                is_active INTEGER DEFAULT '1' NOT NULL,
                created_by TEXT DEFAULT 'system' NOT NULL,
                created_at TEXT DEFAULT (datetime('now')) NOT NULL,
                last_login TEXT,
                {unique_sql}
            )
            """
        )
        connection.execute(
            """
            INSERT INTO users_unique_variant
            SELECT * FROM users
            """
        )
        connection.execute("DROP TABLE users")
        connection.execute(
            "ALTER TABLE users_unique_variant RENAME TO users"
        )
        connection.execute(
            "CREATE INDEX idx_users_username ON users(username)"
        )
        connection.execute("CREATE INDEX idx_users_role ON users(role)")
        if variant == "duplicate":
            connection.execute(
                "CREATE UNIQUE INDEX unexpected_duplicate_user "
                "ON users(username)"
            )
        connection.commit()


def _append_table_constraint(
    path: Path,
    table: str,
    definition: str,
) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=substr(sql, 1, length(sql) - 1) || ', ' || ? || ')'
            WHERE type='table' AND name=?
            """,
            (definition, table),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _replace_findings_with_historical_order(path: Path) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            """
            CREATE TABLE findings_historical (
                id TEXT NOT NULL PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score FLOAT DEFAULT 0.0 NOT NULL,
                cvss_vector TEXT DEFAULT '' NOT NULL,
                confidence FLOAT DEFAULT 1.0 NOT NULL,
                mitre_technique TEXT,
                mitre_tactic TEXT,
                evidence_json TEXT DEFAULT '{}' NOT NULL,
                remediation TEXT DEFAULT '',
                host TEXT,
                validated INTEGER DEFAULT 0 NOT NULL,
                false_positive INTEGER DEFAULT 0 NOT NULL,
                discovered_at TEXT DEFAULT (datetime('now')) NOT NULL,
                trace_id TEXT DEFAULT '' NOT NULL,
                CONSTRAINT fk_findings_campaign
                    FOREIGN KEY(campaign_id)
                    REFERENCES campaigns(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            INSERT INTO findings_historical(
                id, campaign_id, module_id, title, description, severity,
                cvss_score, cvss_vector, confidence, mitre_technique,
                mitre_tactic, evidence_json, remediation, host, validated,
                false_positive, discovered_at, trace_id
            )
            SELECT
                id, campaign_id, module_id, title, description, severity,
                cvss_score, cvss_vector, confidence, mitre_technique,
                mitre_tactic, evidence_json, remediation, host, validated,
                false_positive, discovered_at, trace_id
            FROM findings
            """
        )
        connection.execute("DROP TABLE findings")
        connection.execute(
            "ALTER TABLE findings_historical RENAME TO findings"
        )
        connection.execute(
            "CREATE INDEX idx_findings_campaign ON findings(campaign_id)"
        )
        connection.execute(
            "CREATE INDEX idx_findings_severity ON findings(severity)"
        )
        connection.execute(
            "CREATE INDEX idx_findings_fp ON findings(false_positive)"
        )
        connection.execute(
            "CREATE INDEX idx_findings_mitre ON findings(mitre_technique)"
        )
        connection.execute(
            "CREATE INDEX idx_findings_cvss ON findings(cvss_score)"
        )
        connection.commit()


def _replace_campaigns_with_nocase_primary_key(path: Path) -> None:
    with _connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            """
            CREATE TABLE campaigns_nocase (
                id TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
                name TEXT NOT NULL,
                client TEXT DEFAULT 'Internal' NOT NULL,
                operator TEXT DEFAULT 'unknown' NOT NULL,
                noise_profile TEXT DEFAULT 'stealth' NOT NULL,
                status TEXT DEFAULT 'created' NOT NULL,
                scope_json TEXT DEFAULT '[]' NOT NULL,
                targets_json TEXT DEFAULT '[]' NOT NULL,
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')) NOT NULL,
                updated_at TEXT DEFAULT (datetime('now')) NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO campaigns_nocase
            SELECT * FROM campaigns
            """
        )
        connection.execute("DROP TABLE campaigns")
        connection.execute(
            "ALTER TABLE campaigns_nocase RENAME TO campaigns"
        )
        connection.commit()


def _weaken_ticket_hash_check_with_comment(path: Path) -> None:
    pattern = re.compile(
        r"""
        CONSTRAINT\s+ck_ws_ticket_hash\s+
        CHECK\s*\(\s*
        length\s*\(\s*ticket_hash\s*\)\s*=\s*64\s+
        AND\s+ticket_hash\s+NOT\s+GLOB\s+
        '\*\[\^0-9a-f\]\*'\s*
        \)
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    expected_fragment = (
        "CONSTRAINT ck_ws_ticket_hash CHECK ("
        "length(ticket_hash)=64 AND "
        "ticket_hash NOT GLOB '*[^0-9a-f]*')"
    )
    replacement = (
        "CONSTRAINT ck_ws_ticket_hash CHECK /* parser gap */ (1) "
        f"/* {expected_fragment} */"
    )
    with _connect(path) as connection:
        row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='websocket_tickets'
            """
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise AssertionError("ticket table fixture source is absent")
        rewritten, count = pattern.subn(replacement, row[0], count=1)
        if count != 1:
            raise AssertionError("ticket check fixture source is absent")
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=?
            WHERE type='table' AND name='websocket_tickets'
            """,
            (rewritten,),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _replace_ticket_contract_fragment(
    path: Path,
    source_pattern: str,
    replacement: str,
) -> None:
    with _connect(path) as connection:
        row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='websocket_tickets'
            """
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise AssertionError("ticket table fixture source is absent")
        rewritten, count = re.subn(
            source_pattern,
            replacement,
            row[0],
            count=1,
            flags=re.IGNORECASE,
        )
        if count != 1:
            raise AssertionError("ticket literal fixture source is absent")
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=?
            WHERE type='table' AND name='websocket_tickets'
            """,
            (rewritten,),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _spoof_audit_autoincrement_with_comment(path: Path) -> None:
    with _connect(path) as connection:
        row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='audit_log'
            """
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise AssertionError("audit table fixture source is absent")
        rewritten, count = re.subn(
            r"\bAUTOINCREMENT\b",
            "/* AUTOINCREMENT */",
            row[0],
            count=1,
            flags=re.IGNORECASE,
        )
        if count != 1:
            raise AssertionError("audit AUTOINCREMENT fixture source is absent")
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=?
            WHERE type='table' AND name='audit_log'
            """,
            (rewritten,),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def _weaken_blocked_check_with_comment(path: Path) -> None:
    pattern = re.compile(
        r"""
        CONSTRAINT\s+ck_rate_limit_events_blocked_bool\s+
        CHECK\s*\(\s*blocked\s+IN\s*\(\s*0\s*,\s*1\s*\)\s*\)
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    expected_fragment = (
        "CONSTRAINT ck_rate_limit_events_blocked_bool "
        "CHECK (blocked IN (0, 1))"
    )
    replacement = (
        "CONSTRAINT ck_rate_limit_events_blocked_bool "
        "CHECK /* parser gap */ (1) "
        f"/* {expected_fragment} */"
    )
    with _connect(path) as connection:
        row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='rate_limit_events'
            """
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise AssertionError("rate-limit table fixture source is absent")
        rewritten, count = pattern.subn(replacement, row[0], count=1)
        if count != 1:
            raise AssertionError("blocked-check fixture source is absent")
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql=?
            WHERE type='table' AND name='rate_limit_events'
            """,
            (rewritten,),
        )
        connection.execute(
            "PRAGMA schema_version="
            f"{int(connection.execute('PRAGMA schema_version').fetchone()[0]) + 1}"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()


def test_empty_base_upgrades_to_real_0008_head() -> None:
    with _database("empty") as path:
        _upgrade(path, "head")
        with _connect(path) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            foreign_keys = int(
                connection.execute("PRAGMA foreign_keys").fetchone()[0]
            )
        _require_fixed(
            _version(path) == "0008"
            and {"module_runs", "rate_limit_events", "websocket_tickets"}
            <= tables
            and _complete_managed_contract_is_exact(path)
            and foreign_keys == 1,
            "empty-base upgrade did not produce the managed 0008 schema",
        )


@pytest.mark.parametrize(
    "starting_revision",
    ["0001", "0002", "0003", "0004", "0005", "0006", "0007"],
)
def test_each_supported_historical_revision_upgrades_to_0008(
    starting_revision: str,
) -> None:
    with _database(f"historical-{starting_revision}") as path:
        _upgrade(path, starting_revision)
        with _connect(path) as connection:
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES('c1', 'campaign')"
            )
            connection.execute(
                """
                INSERT INTO users(id, username, hashed_password)
                VALUES('u1', 'account', 'hash')
                """
            )
            connection.commit()
        _upgrade(path, "0008")
        with _connect(path) as connection:
            preserved = (
                connection.execute(
                    "SELECT count(*) FROM campaigns WHERE id='c1'"
                ).fetchone()[0]
                == 1
                and connection.execute(
                    "SELECT count(*) FROM users WHERE id='u1'"
                ).fetchone()[0]
                == 1
            )
        _require_fixed(
            _version(path) == "0008"
            and preserved
            and _complete_managed_contract_is_exact(path),
            "supported historical revision did not upgrade losslessly",
        )


def test_exact_0007_is_catalog_and_data_noop_except_version() -> None:
    with _database("exact-noop") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        before = _snapshot(path)
        identity_before = _physical_catalog_identity(path)
        _upgrade(path, "0008")
        after = _snapshot(path)
        identity_after = _physical_catalog_identity(path)
        _require_fixed(
            before[0] == "0007"
            and after[0] == "0008"
            and after[1:] == before[1:]
            and identity_after == identity_before,
            "exact revision 0007 changed outside Alembic version state",
        )


def test_missing_owned_tables_and_indexes_are_recreated_with_data_preserved(
) -> None:
    with _database("missing") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        with _connect(path) as connection:
            connection.execute("DROP TABLE module_runs")
            connection.execute("DROP TABLE rate_limit_events")
            connection.execute("DROP INDEX idx_findings_mitre")
            connection.execute("DROP INDEX idx_creds_username")
            connection.commit()
        protected = _data(path)
        _upgrade(path, "0008")
        with _connect(path) as connection:
            objects = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','index')"
                )
            }
        _require_fixed(
            _version(path) == "0008"
            and {
                "module_runs",
                "rate_limit_events",
                "idx_findings_mitre",
                "idx_creds_username",
            }
            <= objects
            and _complete_managed_contract_is_exact(path)
            and all(
                rows == dict(_data(path)).get(table)
                for table, rows in protected
            ),
            "missing managed objects were not reconciled losslessly",
        )


@pytest.mark.parametrize("object_kind", ["view", "index", "trigger"])
def test_optional_table_name_collision_is_rejected_before_mutation(
    object_kind: str,
) -> None:
    statements = {
        "view": "CREATE VIEW module_runs AS SELECT 1 AS id",
        "index": "CREATE INDEX module_runs ON campaigns(name)",
        "trigger": (
            "CREATE TRIGGER module_runs AFTER INSERT ON campaigns "
            "BEGIN SELECT 1; END"
        ),
    }
    with _database(f"optional-name-{object_kind}") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute("DROP TABLE module_runs")
            connection.execute(statements[object_kind])
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "optional-table name collision was not rejected atomically",
        )


def test_representative_legacy_catalog_converges_and_is_repeat_stable() -> None:
    with _database("legacy") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        with _connect(path) as connection:
            connection.execute("DROP INDEX idx_findings_mitre")
            connection.execute(
                "CREATE INDEX idx_findings_validated ON findings(validated)"
            )
            connection.execute("DROP TABLE module_runs")
            connection.execute("DROP TABLE rate_limit_events")
            connection.commit()
        ticket_before = dict(_data(path))["websocket_tickets"]
        _upgrade(path, "0008")
        first = _snapshot(path)
        command.stamp(_config(path), "0007")
        _upgrade(path, "0008")
        second = _snapshot(path)
        _require_fixed(
            first == second
            and _complete_managed_contract_is_exact(path)
            and dict(_data(path))["websocket_tickets"] == ticket_before,
            "legacy reconciliation was unstable or changed ticket state",
        )


def test_runtime_origin_stamped_0007_converges_to_fixed_contract() -> None:
    with _database("runtime-origin") as path:
        asyncio.run(_runtime_bootstrap(path))
        with _connect(path) as connection:
            before_order = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(findings)"
                )
            )
            connection.execute(
                """
                CREATE TABLE alembic_version(
                    version_num VARCHAR(32) NOT NULL,
                    CONSTRAINT alembic_version_pkc PRIMARY KEY(version_num)
                )
                """
            )
            connection.execute(
                "INSERT INTO alembic_version(version_num) VALUES('0007')"
            )
            connection.commit()
        _seed_graph(path)
        before_data = _logical_data(path)
        _upgrade(path, "0008")
        with _connect(path) as connection:
            after_order = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(findings)"
                )
            )
        _require_fixed(
            before_order.index("trace_id") < before_order.index("evidence_json")
            and after_order.index("trace_id") > after_order.index("discovered_at"),
            "runtime-origin findings order did not converge",
        )
        _require_fixed(
            _complete_managed_contract_is_exact(path),
            "runtime-origin catalog did not reach the fixed contract",
        )
        after_data = dict(_logical_data(path))
        _require_fixed(
            all(
                rows == after_data.get(table)
                for table, rows in before_data
            ),
            "runtime-origin application rows were not preserved",
        )


def test_historical_cvss_before_confidence_order_converges_losslessly(
) -> None:
    with _database("historical-findings-order") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _replace_findings_with_historical_order(path)
        with _connect(path) as connection:
            before_order = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(findings)"
                )
            )
            before_row = connection.execute(
                """
                SELECT
                    id, campaign_id, module_id, title, description,
                    severity, confidence, mitre_technique, mitre_tactic,
                    cvss_score, cvss_vector, evidence_json, remediation,
                    host, validated, false_positive, discovered_at, trace_id
                FROM findings
                """
            ).fetchone()
        _upgrade(path, "0008")
        with _connect(path) as connection:
            after_order = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(findings)"
                )
            )
            after_row = connection.execute(
                """
                SELECT
                    id, campaign_id, module_id, title, description,
                    severity, confidence, mitre_technique, mitre_tactic,
                    cvss_score, cvss_vector, evidence_json, remediation,
                    host, validated, false_positive, discovered_at, trace_id
                FROM findings
                """
            ).fetchone()
        _require_fixed(
            before_order.index("cvss_score")
            < before_order.index("confidence")
            and after_order.index("confidence")
            < after_order.index("cvss_score")
            and before_row is not None
            and after_row is not None
            and tuple(before_row) == tuple(after_row)
            and _complete_managed_contract_is_exact(path),
            "historical findings order did not converge losslessly",
        )


def test_missing_foreign_key_and_blocked_check_converge(
) -> None:
    with _database("structural-drift") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _rewrite_table_sql(
            path,
            "credentials",
            ", \n\tCONSTRAINT fk_credentials_host FOREIGN KEY(host_id) "
            "REFERENCES hosts (id) ON DELETE SET NULL",
            "",
        )
        _rewrite_table_sql(
            path,
            "rate_limit_events",
            ", \n\tCONSTRAINT ck_rate_limit_events_blocked_bool "
            "CHECK (blocked IN (0, 1))",
            "",
        )
        before_rows = _data(path)
        _upgrade(path, "0008")
        with _connect(path) as connection:
            credential_columns = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(credentials)"
                )
            )
            credential_fks = {
                (
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    str(row[6]),
                )
                for row in connection.execute(
                    "PRAGMA foreign_key_list(credentials)"
                )
            }
            rate_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='rate_limit_events'
                    """
                ).fetchone()[0]
            )
        _require_fixed(
            credential_columns[10] == "cracked_value_enc"
            and ("hosts", "host_id", "id", "SET NULL") in credential_fks
            and "ck_rate_limit_events_blocked_bool" in rate_sql
            and _complete_managed_contract_is_exact(path)
            and dict(_data(path))["credentials"]
            == dict(before_rows)["credentials"],
            "structural legacy drift did not converge losslessly",
        )


def test_safe_legacy_credential_shape_and_order_converges() -> None:
    with _database("credential-shape") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _rewrite_table_sql(
            path,
            "credentials",
            "cracked_value_enc TEXT",
            "cracked_value TEXT",
        )
        before = dict(_data(path))["credentials"]
        _upgrade(path, "0008")
        with _connect(path) as connection:
            columns = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(credentials)"
                )
            )
        _require_fixed(
            "cracked_value" not in columns
            and columns[10] == "cracked_value_enc"
            and _complete_managed_contract_is_exact(path)
            and dict(_data(path))["credentials"] == before,
            "safe legacy credential shape did not converge losslessly",
        )


@pytest.mark.parametrize("variant", ["duplicate", "nocase"])
def test_noncanonical_unique_metadata_is_rejected_without_mutation(
    variant: str,
) -> None:
    with _database(f"unique-{variant}") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _replace_users_unique_contract(path, variant)
        with _connect(path) as connection:
            index_rows = list(
                connection.execute("PRAGMA index_list(users)")
            )
            unique_rows = [
                row
                for row in index_rows
                if str(row[3]) == "u"
            ]
            collations = tuple(
                str(detail[4]).upper()
                for row in unique_rows
                for detail in connection.execute(
                    f'PRAGMA index_xinfo("{str(row[1])}")'  # noqa: S608
                )
                if bool(detail[5])
            )
        fixture_is_authentic = (
            variant == "duplicate"
            and len(unique_rows) == 1
            and sum(
                bool(row[2]) and str(row[3]) == "c"
                for row in index_rows
            )
            == 1
        ) or (
            variant == "nocase"
            and len(unique_rows) == 1
            and collations == ("NOCASE",)
        )
        _require_fixed(
            fixture_is_authentic,
            "noncanonical unique fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "noncanonical unique metadata was not rejected atomically",
        )


def test_nocase_managed_text_primary_key_is_rejected_without_mutation(
) -> None:
    with _database("nocase-primary-key") as path:
        _upgrade(path, "0007")
        _replace_campaigns_with_nocase_primary_key(path)
        with _connect(path) as connection:
            primary_rows = [
                row
                for row in connection.execute(
                    "PRAGMA index_list(campaigns)"
                )
                if str(row[3]).lower() == "pk"
            ]
            primary_columns = (
                ()
                if len(primary_rows) != 1
                else tuple(
                    (
                        int(row[1]),
                        None if row[2] is None else str(row[2]),
                        int(row[3]),
                        str(row[4]).upper(),
                        int(row[5]),
                    )
                    for row in connection.execute(
                        f'PRAGMA index_xinfo("{str(primary_rows[0][1])}")'
                    )
                )
            )
        fixture_is_authentic = (
            len(primary_rows) == 1
            and primary_columns
            and primary_columns[0] == (0, "id", 0, "NOCASE", 1)
        )
        _require_fixed(
            bool(fixture_is_authentic),
            "NOCASE primary-key fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "NOCASE primary-key metadata was not rejected atomically",
        )


def test_ticket_generated_hidden_column_is_rejected_without_mutation(
) -> None:
    with _database("ticket-hidden-column") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute(
                """
                ALTER TABLE websocket_tickets
                ADD COLUMN ticket_marker TEXT
                GENERATED ALWAYS AS (credential_kind) VIRTUAL
                """
            )
            connection.commit()
            visible_count = len(
                tuple(
                    connection.execute(
                        "PRAGMA table_info(websocket_tickets)"
                    )
                )
            )
            extended_rows = tuple(
                connection.execute(
                    "PRAGMA table_xinfo(websocket_tickets)"
                )
            )
        fixture_is_authentic = (
            visible_count == 12
            and len(extended_rows) == 13
            and str(extended_rows[-1][1]) == "ticket_marker"
            and int(extended_rows[-1][6]) != 0
        )
        _require_fixed(
            fixture_is_authentic,
            "generated-column fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "generated ticket column was not rejected atomically",
        )


def test_ticket_index_sql_drift_is_rejected_without_mutation() -> None:
    with _database("ticket-index-sql") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                """
                CREATE INDEX idx_ws_tickets_expires
                ON websocket_tickets(expires_at COLLATE BINARY ASC)
                """
            )
            connection.commit()
            index_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='index' AND name='idx_ws_tickets_expires'
                    """
                ).fetchone()[0]
            )
            key_rows = tuple(
                row
                for row in connection.execute(
                    "PRAGMA index_xinfo(idx_ws_tickets_expires)"
                )
                if bool(row[5])
            )
        fixture_is_authentic = (
            "COLLATE BINARY ASC" in index_sql.upper()
            and len(key_rows) == 1
            and int(key_rows[0][1]) == 10
            and str(key_rows[0][2]) == "expires_at"
            and int(key_rows[0][3]) == 0
            and str(key_rows[0][4]).upper() == "BINARY"
        )
        _require_fixed(
            fixture_is_authentic,
            "index-definition drift fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "ticket index definition drift was not rejected atomically",
        )


def test_ticket_check_comment_differential_is_rejected_without_mutation(
) -> None:
    with _database("ticket-check-comment") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _weaken_ticket_hash_check_with_comment(path)
        weak_check_accepted = False
        comment_present = False
        with _connect(path) as connection:
            table_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='websocket_tickets'
                    """
                ).fetchone()[0]
            )
            comment_present = "parser gap" in table_sql
            connection.execute("SAVEPOINT check_authenticity")
            try:
                connection.execute(
                    """
                    INSERT INTO websocket_tickets(
                        ticket_hash, campaign_id, user_id, credential_kind,
                        api_key_id, required_scope, created_at, expires_at
                    ) VALUES(
                        ?, 'c1', 'u1', 'api_key', 'a1', 'read',
                        '2098-01-01T00:00:00.000Z',
                        '2098-01-01T00:01:00.000Z'
                    )
                    """,
                    ("short",),
                )
                weak_check_accepted = True
            except sqlite3.IntegrityError:
                weak_check_accepted = False
            finally:
                connection.execute(
                    "ROLLBACK TO SAVEPOINT check_authenticity"
                )
                connection.execute("RELEASE SAVEPOINT check_authenticity")
        _require_fixed(
            comment_present and weak_check_accepted,
            "comment-bearing weakened CHECK fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "comment-bearing weakened CHECK was not rejected atomically",
        )


@pytest.mark.parametrize("variant", ["scope", "hash"])
def test_ticket_quoted_literal_case_drift_is_rejected_without_mutation(
    variant: str,
) -> None:
    with _database(f"ticket-literal-{variant}") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        if variant == "scope":
            _replace_ticket_contract_fragment(
                path,
                r"required_scope\s*=\s*'read'",
                "required_scope='READ'",
            )
            ticket_hash = "b" * 64
            required_scope = "READ"
        else:
            _replace_ticket_contract_fragment(
                path,
                r"'\*\[\^0-9a-f\]\*'",
                "'*[^0-9A-F]*'",
            )
            ticket_hash = "B" * 64
            required_scope = "read"
        altered_literal_accepted = False
        with _connect(path) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO websocket_tickets(
                        ticket_hash, campaign_id, user_id, credential_kind,
                        api_key_id, required_scope, created_at, expires_at
                    ) VALUES(
                        ?, 'c1', 'u1', 'api_key', 'a1', ?,
                        '2098-01-01T00:02:00.000Z',
                        '2098-01-01T00:03:00.000Z'
                    )
                    """,
                    (ticket_hash, required_scope),
                )
                connection.commit()
                altered_literal_accepted = True
            except sqlite3.IntegrityError:
                altered_literal_accepted = False
        _require_fixed(
            altered_literal_accepted,
            "quoted-literal drift fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "quoted-literal drift was not rejected atomically",
        )


def test_audit_autoincrement_comment_spoof_is_rejected_without_mutation(
) -> None:
    with _database("audit-autoincrement-comment") as path:
        _upgrade(path, "0007")
        _spoof_audit_autoincrement_with_comment(path)
        with _connect(path) as connection:
            table_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='audit_log'
                    """
                ).fetchone()[0]
            )
        without_comments = re.sub(
            r"/\*.*?\*/|--[^\r\n]*",
            "",
            table_sql,
            flags=re.DOTALL,
        )
        _require_fixed(
            "AUTOINCREMENT" in table_sql.upper()
            and "AUTOINCREMENT" not in without_comments.upper(),
            "comment-bearing AUTOINCREMENT fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "comment-bearing AUTOINCREMENT spoof was not rejected atomically",
        )


def test_rate_limit_check_comment_spoof_is_rejected_without_mutation() -> None:
    with _database("blocked-check-comment") as path:
        _upgrade(path, "0007")
        _weaken_blocked_check_with_comment(path)
        invalid_flag_accepted = False
        comment_present = False
        with _connect(path) as connection:
            table_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='rate_limit_events'
                    """
                ).fetchone()[0]
            )
            comment_present = "parser gap" in table_sql
            connection.execute("SAVEPOINT check_authenticity")
            try:
                connection.execute(
                    """
                    INSERT INTO rate_limit_events(
                        ip_address, bucket, blocked
                    ) VALUES('192.0.2.1', 'auth', 2)
                    """
                )
                invalid_flag_accepted = True
            except sqlite3.IntegrityError:
                invalid_flag_accepted = False
            finally:
                connection.execute(
                    "ROLLBACK TO SAVEPOINT check_authenticity"
                )
                connection.execute("RELEASE SAVEPOINT check_authenticity")
        _require_fixed(
            comment_present and invalid_flag_accepted,
            "comment-bearing weakened blocked CHECK fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "comment-bearing weakened blocked CHECK was not rejected atomically",
        )


def test_reserved_index_on_unrelated_table_is_rejected_without_mutation(
) -> None:
    with _database("reserved-index-owner") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute("DROP INDEX idx_findings_mitre")
            connection.execute(
                """
                CREATE TABLE operator_notes(
                    id TEXT NOT NULL PRIMARY KEY,
                    note TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX idx_findings_mitre ON operator_notes(note)"
            )
            connection.execute(
                "INSERT INTO operator_notes(id, note) VALUES('n1', 'note')"
            )
            connection.commit()
            index_owner = connection.execute(
                """
                SELECT tbl_name FROM sqlite_master
                WHERE type='index' AND name='idx_findings_mitre'
                """
            ).fetchone()
        fixture_is_authentic = (
            index_owner is not None
            and str(index_owner[0]) == "operator_notes"
        )
        _require_fixed(
            fixture_is_authentic,
            "reserved-index owner fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "reserved index on unrelated table was not rejected atomically",
        )


def test_duplicate_non_ticket_foreign_key_is_rejected_without_mutation(
) -> None:
    with _database("duplicate-non-ticket-fk") as path:
        _upgrade(path, "0007")
        _append_table_constraint(
            path,
            "findings",
            "CONSTRAINT duplicate_findings_campaign "
            "FOREIGN KEY(campaign_id) REFERENCES campaigns(id) "
            "ON DELETE CASCADE",
        )
        with _connect(path) as connection:
            foreign_keys = tuple(
                connection.execute("PRAGMA foreign_key_list(findings)")
            )
        fixture_is_authentic = (
            len(foreign_keys) == 2
            and len(
                {
                    (
                        str(row[2]),
                        str(row[3]),
                        str(row[4]),
                        str(row[5]).upper(),
                        str(row[6]).upper(),
                    )
                    for row in foreign_keys
                }
            )
            == 1
        )
        _require_fixed(
            fixture_is_authentic,
            "duplicate foreign-key fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "duplicate non-ticket foreign key was not rejected atomically",
        )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("orphan", _DATA_ERROR),
        ("duplicate", _DATA_ERROR),
        ("null", _DATA_ERROR),
        ("flag", _DATA_ERROR),
        ("timestamp", _DATA_ERROR),
        ("ambiguous", _CATALOG_ERROR),
        ("extra-check", _CATALOG_ERROR),
        ("other-flag", _DATA_ERROR),
    ],
)
def test_rejected_legacy_state_is_atomic(
    mutation: str,
    expected: str,
) -> None:
    with _database(f"reject-{mutation}") as path:
        _upgrade(path, "0007")
        if mutation == "duplicate":
            _remove_users_unique_constraint(path)
        elif mutation == "null":
            _rewrite_table_sql(
                path,
                "findings",
                "cvss_vector TEXT DEFAULT ('') NOT NULL",
                "cvss_vector TEXT DEFAULT ('')",
            )
        elif mutation == "extra-check":
            _append_check_constraint(path, "campaigns")
        with _connect(path) as connection:
            if mutation == "orphan":
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute(
                    """
                    INSERT INTO hosts(id, campaign_id, ip_address)
                    VALUES('h1', 'missing', '192.0.2.2')
                    """
                )
            elif mutation == "duplicate":
                connection.execute(
                    """
                    INSERT INTO users(id, username, hashed_password)
                    VALUES('u1', 'duplicate', 'hash')
                    """
                )
                connection.execute(
                    """
                    INSERT INTO users(id, username, hashed_password)
                    VALUES('u2', 'duplicate', 'hash')
                    """
                )
            elif mutation == "null":
                connection.execute(
                    """
                    INSERT INTO campaigns(id, name)
                    VALUES('c1', 'campaign')
                    """,
                )
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title, description,
                        severity, cvss_vector
                    ) VALUES(
                        'f1', 'c1', 'module', 'finding', 'description',
                        'high', NULL
                    )
                    """
                )
            elif mutation == "flag":
                connection.execute("PRAGMA ignore_check_constraints=ON")
                connection.execute(
                    """
                    INSERT INTO rate_limit_events(ip_address, bucket, blocked)
                    VALUES('192.0.2.3', 'login', 2)
                    """
                )
            elif mutation == "timestamp":
                connection.execute(
                    """
                    INSERT INTO revoked_access_tokens(
                        jti, user_id, expires_at
                    ) VALUES('j1', 'u1', 'not-a-timestamp')
                    """
                )
            elif mutation == "ambiguous":
                connection.execute(
                    "CREATE TRIGGER managed_ambiguous AFTER INSERT ON users "
                    "BEGIN SELECT 1; END"
                )
            elif mutation == "extra-check":
                pass
            elif mutation == "other-flag":
                connection.execute(
                    """
                    INSERT INTO users(
                        id, username, hashed_password, is_active
                    ) VALUES('u1', 'account', 'hash', 2)
                    """
                )
            else:
                raise AssertionError("unknown mutation")
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == expected
            and after == before
            and _version(path) == "0007",
            "rejected reconciliation mutated catalog, data, or revision",
        )


@pytest.mark.parametrize(
    "flag_case",
    [
        "module-success",
        "finding-validated",
        "finding-false-positive",
        "host-domain-controller",
        "credential-cracked",
        "user-active",
        "api-key-active",
        "refresh-revoked",
    ],
)
def test_each_non_rate_integer_flag_rejects_non_boolean_data(
    flag_case: str,
) -> None:
    statements = {
        "module-success": (
            "INSERT INTO module_runs("
            "id, campaign_id, module_id, outcome, success"
            ") VALUES('m1', 'c1', 'module', 'outcome', 2)"
        ),
        "finding-validated": (
            "INSERT INTO findings("
            "id, campaign_id, module_id, title, description, severity, "
            "validated"
            ") VALUES("
            "'f1', 'c1', 'module', 'finding', 'description', 'high', 2"
            ")"
        ),
        "finding-false-positive": (
            "INSERT INTO findings("
            "id, campaign_id, module_id, title, description, severity, "
            "false_positive"
            ") VALUES("
            "'f1', 'c1', 'module', 'finding', 'description', 'high', 2"
            ")"
        ),
        "host-domain-controller": (
            "INSERT INTO hosts(id, campaign_id, ip_address, is_dc) "
            "VALUES('h1', 'c1', '192.0.2.8', 2)"
        ),
        "credential-cracked": (
            "INSERT INTO credentials("
            "id, campaign_id, username, cred_type, cracked"
            ") VALUES('k1', 'c1', 'account', 'password', 2)"
        ),
        "user-active": (
            "INSERT INTO users(id, username, hashed_password, is_active) "
            "VALUES('u1', 'account', 'hash', 2)"
        ),
        "api-key-active": (
            "INSERT INTO api_keys("
            "id, user_id, name, key_hash, key_prefix, is_active"
            ") VALUES('a1', 'u1', 'key', 'hash', 'prefix', 2)"
        ),
        "refresh-revoked": (
            "INSERT INTO refresh_tokens("
            "id, user_id, is_revoked, expires_at"
            ") VALUES('r1', 'u1', 2, '2099-01-01 00:00:00')"
        ),
    }
    with _database(f"flag-{flag_case}") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            if flag_case in {
                "module-success",
                "finding-validated",
                "finding-false-positive",
                "host-domain-controller",
                "credential-cracked",
            }:
                connection.execute(
                    "INSERT INTO campaigns(id, name) "
                    "VALUES('c1', 'campaign')"
                )
            if flag_case in {"api-key-active", "refresh-revoked"}:
                connection.execute(
                    "INSERT INTO users(id, username, hashed_password) "
                    "VALUES('u1', 'account', 'hash')"
                )
            connection.execute(statements[flag_case])
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _DATA_ERROR
            and after == before
            and _version(path) == "0007",
            "non-Boolean integer flag was not rejected atomically",
        )


@pytest.mark.parametrize(
    "variant",
    [
        "hash",
        "kind",
        "created",
        "expires",
        "consumed",
        "time-order",
        "source-shape",
    ],
)
def test_ticket_row_check_violations_are_rejected_before_reconciliation(
    variant: str,
) -> None:
    with _database(f"ticket-row-{variant}") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        values: dict[str, object | None] = {
            "ticket_hash": "b" * 64,
            "credential_kind": "api_key",
            "bearer_subject": None,
            "bearer_jti": None,
            "bearer_expires_at": None,
            "api_key_id": "a1",
            "required_scope": "read",
            "created_at": "2098-01-01T00:00:00.000Z",
            "expires_at": "2098-01-01T00:01:00.000Z",
            "consumed_at": None,
        }
        if variant == "hash":
            values["ticket_hash"] = "short"
        elif variant == "kind":
            values["credential_kind"] = "unknown"
        elif variant == "created":
            values["created_at"] = "not-a-timestamp"
        elif variant == "expires":
            values["expires_at"] = "not-a-timestamp"
        elif variant == "consumed":
            values["consumed_at"] = "not-a-timestamp"
        elif variant == "time-order":
            values["expires_at"] = "2097-12-31T23:59:59.000Z"
        else:
            values["required_scope"] = "write"
        with _connect(path) as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                """
                INSERT INTO websocket_tickets(
                    ticket_hash, campaign_id, user_id, credential_kind,
                    bearer_subject, bearer_jti, bearer_expires_at,
                    api_key_id, required_scope, created_at, expires_at,
                    consumed_at
                ) VALUES(?, 'c1', 'u1', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["ticket_hash"],
                    values["credential_kind"],
                    values["bearer_subject"],
                    values["bearer_jti"],
                    values["bearer_expires_at"],
                    values["api_key_id"],
                    values["required_scope"],
                    values["created_at"],
                    values["expires_at"],
                    values["consumed_at"],
                ),
            )
            connection.execute("PRAGMA ignore_check_constraints=OFF")
            connection.execute("DROP TABLE module_runs")
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _DATA_ERROR
            and after == before
            and _version(path) == "0007",
            "invalid ticket row was not rejected before reconciliation",
        )


@pytest.mark.parametrize(
    "orphan_kind",
    ["campaign", "user", "api-key"],
)
def test_ticket_foreign_key_orphans_are_rejected_without_mutation(
    orphan_kind: str,
) -> None:
    with _database(f"ticket-orphan-{orphan_kind}") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        values = {
            "campaign": ("missing", "u1", "a1"),
            "user": ("c1", "missing", "a1"),
            "api-key": ("c1", "u1", "missing"),
        }[orphan_kind]
        with _connect(path) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                """
                INSERT INTO websocket_tickets(
                    ticket_hash, campaign_id, user_id, credential_kind,
                    api_key_id, required_scope, created_at, expires_at
                ) VALUES(
                    ?, ?, ?, 'api_key', ?, 'read',
                    '2098-01-01T00:00:00.000Z',
                    '2098-01-01T00:01:00.000Z'
                )
                """,
                ("b" * 64, *values),
            )
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _DATA_ERROR
            and after == before
            and _version(path) == "0007",
            "ticket foreign-key orphan was not rejected atomically",
        )


@pytest.mark.parametrize("variant", ["duplicate", "deferrable"])
def test_noncanonical_ticket_foreign_key_is_rejected_without_mutation(
    variant: str,
) -> None:
    definition = (
        "CONSTRAINT unexpected_ws_campaign "
        "FOREIGN KEY(campaign_id) REFERENCES campaigns(id) "
        "ON DELETE CASCADE"
    )
    if variant == "deferrable":
        definition += " DEFERRABLE INITIALLY DEFERRED"
    with _database(f"ticket-fk-{variant}") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        _append_table_constraint(path, "websocket_tickets", definition)
        with _connect(path) as connection:
            foreign_key_count = len(
                tuple(
                    connection.execute(
                        "PRAGMA foreign_key_list(websocket_tickets)"
                    )
                )
            )
            table_sql = str(
                connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='websocket_tickets'
                    """
                ).fetchone()[0]
            )
        fixture_is_authentic = foreign_key_count == 4 and (
            variant != "deferrable"
            or "DEFERRABLE INITIALLY DEFERRED" in table_sql
        )
        _require_fixed(
            fixture_is_authentic,
            "noncanonical ticket foreign-key fixture was not authentic",
        )
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "noncanonical ticket foreign key was not rejected atomically",
        )


def test_downgrade_is_fixed_forward_only_and_has_zero_mutation() -> None:
    with _database("downgrade") as path:
        _upgrade(path, "0008")
        before = _snapshot(path)
        observed = ""
        try:
            _downgrade(path, "0007")
        except RuntimeError as exc:
            observed = str(exc)
        _require_fixed(
            observed == _FORWARD_ONLY_ERROR
            and _snapshot(path) == before
            and _version(path) == "0008",
            "revision 0008 downgrade mutated forward-only state",
        )


def test_unsupported_dialect_is_rejected_with_fixed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module(
        "migrations.versions.0008_reconcile_schema_parity"
    )
    fake_bind = SimpleNamespace(dialect=SimpleNamespace(name="unsupported"))
    monkeypatch.setattr(migration.op, "get_bind", lambda: fake_bind)
    observed = ""
    try:
        migration.upgrade()
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _DIALECT_ERROR,
        "revision 0008 accepted an unsupported dialect",
    )


def test_temp_trigger_on_managed_table_is_rejected_before_preflight_reads(
) -> None:
    migration = importlib.import_module(
        "migrations.versions.0008_reconcile_schema_parity"
    )
    with _database("temp-trigger-shadow") as path:
        _upgrade(path, "0007")
        before = _snapshot(path)
        engine = sa.create_engine(f"sqlite:///{path.as_posix()}")
        observed = ""
        temp_trigger_present = False
        try:
            with engine.connect() as connection:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.exec_driver_sql(
                    """
                    CREATE TEMP TRIGGER operator_hook
                    AFTER INSERT ON campaigns
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                try:
                    migration._sqlite_preflight(connection)
                except RuntimeError as exc:
                    observed = str(exc)
                temp_trigger_present = (
                    connection.exec_driver_sql(
                        """
                        SELECT count(*) FROM sqlite_temp_master
                        WHERE type='trigger' AND tbl_name='campaigns'
                        """
                    ).scalar_one()
                    == 1
                )
        finally:
            engine.dispose()
        _require_fixed(
            observed == _CATALOG_ERROR
            and temp_trigger_present
            and _snapshot(path) == before
            and _version(path) == "0007",
            "temporary managed-table trigger was not rejected before reads",
        )


def test_exact_temp_table_shadow_is_rejected_before_preflight_reads() -> None:
    migration = importlib.import_module(
        "migrations.versions.0008_reconcile_schema_parity"
    )
    with _database("temp-table-shadow") as path:
        _upgrade(path, "0007")
        before = _snapshot(path)
        engine = sa.create_engine(f"sqlite:///{path.as_posix()}")
        observed = ""
        temp_table_present = False
        try:
            with engine.connect() as connection:
                source = connection.exec_driver_sql(
                    """
                    SELECT sql FROM main.sqlite_master
                    WHERE type='table' AND name='campaigns'
                    """
                ).scalar_one()
                shadow_sql, replacement_count = re.subn(
                    r"^\s*CREATE\s+TABLE\s+(?:\"campaigns\"|campaigns)",
                    "CREATE TEMP TABLE campaigns",
                    str(source),
                    count=1,
                    flags=re.IGNORECASE,
                )
                _require_fixed(
                    replacement_count == 1,
                    "temporary managed-table fixture was not constructed",
                )
                connection.exec_driver_sql(shadow_sql)
                connection.exec_driver_sql(
                    """
                    CREATE INDEX temp.idx_campaigns_status
                    ON campaigns(status)
                    """
                )
                connection.exec_driver_sql(
                    """
                    CREATE INDEX temp.idx_campaigns_created
                    ON campaigns(created_at)
                    """
                )
                try:
                    migration._sqlite_preflight(connection)
                except RuntimeError as exc:
                    observed = str(exc)
                temp_table_present = (
                    connection.exec_driver_sql(
                        """
                        SELECT count(*) FROM sqlite_temp_master
                        WHERE type='table' AND name='campaigns'
                        """
                    ).scalar_one()
                    == 1
                )
        finally:
            engine.dispose()
        _require_fixed(
            observed == _CATALOG_ERROR
            and temp_table_present
            and _snapshot(path) == before
            and _version(path) == "0007",
            "temporary managed-table shadow was not rejected before reads",
        )


def test_exact_temp_version_table_shadow_is_rejected_before_preflight_reads(
) -> None:
    migration = importlib.import_module(
        "migrations.versions.0008_reconcile_schema_parity"
    )
    with _database("temp-version-shadow") as path:
        _upgrade(path, "0007")
        before = _snapshot(path)
        engine = sa.create_engine(f"sqlite:///{path.as_posix()}")
        observed = ""
        temp_table_present = False
        try:
            with engine.connect() as connection:
                connection.exec_driver_sql(
                    """
                    CREATE TEMP TABLE alembic_version(
                        version_num VARCHAR(32) NOT NULL,
                        CONSTRAINT alembic_version_pkc
                            PRIMARY KEY(version_num)
                    )
                    """
                )
                connection.exec_driver_sql(
                    """
                    INSERT INTO temp.alembic_version(version_num)
                    VALUES('0007')
                    """
                )
                try:
                    migration._sqlite_preflight(connection)
                except RuntimeError as exc:
                    observed = str(exc)
                temp_table_present = (
                    connection.exec_driver_sql(
                        """
                        SELECT count(*) FROM sqlite_temp_master
                        WHERE type='table' AND name='alembic_version'
                        """
                    ).scalar_one()
                    == 1
                )
        finally:
            engine.dispose()
        _require_fixed(
            observed == _CATALOG_ERROR
            and temp_table_present
            and _snapshot(path) == before
            and _version(path) == "0007",
            "temporary version-table shadow was not rejected before reads",
        )


def test_sqlite_audit_autoincrement_and_connection_reuse() -> None:
    with _database("autoincrement") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute(
                "INSERT INTO audit_log(action) VALUES('first')"
            )
            first = int(
                connection.execute(
                    "SELECT max(id) FROM audit_log"
                ).fetchone()[0]
            )
            connection.execute("DELETE FROM audit_log")
            connection.commit()
        _upgrade(path, "0008")
        with _connect(path) as connection:
            connection.execute(
                "INSERT INTO audit_log(action) VALUES('second')"
            )
            second = int(
                connection.execute(
                    "SELECT max(id) FROM audit_log"
                ).fetchone()[0]
            )
            foreign_keys = int(
                connection.execute("PRAGMA foreign_keys").fetchone()[0]
            )
            reusable = connection.execute("SELECT 1").fetchone() == (1,)
        _require_fixed(
            second > first and foreign_keys == 1 and reusable,
            "AUTOINCREMENT, foreign keys, or connection reuse regressed",
        )


def test_injected_version_update_failure_rolls_back_reconciliation() -> None:
    with _database("version-failure") as path:
        _upgrade(path, "0007")
        with _connect(path) as connection:
            connection.execute("DROP TABLE module_runs")
            connection.commit()
        before = _snapshot(path)
        trigger_installed = False

        def install_failure_trigger(
            _connection: object,
            cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            nonlocal trigger_installed
            normalized = re.sub(r"\s+", " ", statement).lower()
            if (
                trigger_installed
                or re.search(
                    r"create table \"?module_runs\"?",
                    normalized,
                )
                is None
            ):
                return
            trigger_installed = True
            cursor.execute(
                """
                CREATE TRIGGER block_revision_0008
                BEFORE UPDATE ON alembic_version
                BEGIN
                    SELECT RAISE(ABORT, 'injected version update failure');
                END
                """
            )

        failed = False
        sa.event.listen(
            sa.engine.Engine,
            "after_cursor_execute",
            install_failure_trigger,
        )
        try:
            try:
                _upgrade(path, "0008")
            except Exception:
                failed = True
        finally:
            sa.event.remove(
                sa.engine.Engine,
                "after_cursor_execute",
                install_failure_trigger,
            )
        _require_fixed(
            trigger_installed
            and failed
            and _snapshot(path) == before
            and _version(path) == "0007",
            "version-update failure did not roll back revision reconciliation",
        )


def test_version_table_trigger_cannot_mutate_application_data() -> None:
    with _database("version-trigger") as path:
        _upgrade(path, "0007")
        _seed_graph(path)
        with _connect(path) as connection:
            connection.execute(
                """
                CREATE TRIGGER mutate_on_revision
                AFTER UPDATE ON alembic_version
                BEGIN
                    UPDATE campaigns
                    SET notes='changed'
                    WHERE id='c1';
                END
                """
            )
            connection.commit()
        before = _snapshot(path)
        observed = _attempt_upgrade(path)
        after = _snapshot(path)
        _require_fixed(
            observed == _CATALOG_ERROR
            and after == before
            and _version(path) == "0007",
            "version-table trigger was not rejected before application mutation",
        )
