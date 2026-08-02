"""Real SQLite coverage for revision 0009 refresh-token families."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import sqlalchemy as sa
from alembic import command

from ares.db.migrations.adoption import migration_config


def _require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def _alembic(
    database_path: Path,
    action: Callable[[object, str], None],
    revision: str,
) -> None:
    engine = sa.create_engine(f"sqlite:///{database_path}")
    try:
        with engine.connect() as connection:
            with migration_config(connection) as config:
                action(config, revision)
    finally:
        engine.dispose()


def _connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _seed_revision_0008(database_path: Path, *, legacy_identifier: str) -> None:
    connection = _connect(database_path)
    try:
        connection.execute(
            "INSERT INTO users(id,username,hashed_password,role) "
            "VALUES('family-user','family-user','fixed-hash','operator')"
        )
        connection.execute(
            "INSERT INTO refresh_tokens(id,user_id,expires_at) "
            "VALUES(?, 'family-user', '2099-01-01T00:00:00.000Z')",
            (legacy_identifier,),
        )
        connection.execute(
            "INSERT INTO campaigns(id,name,operator) "
            "VALUES('family-campaign','Family campaign','family-user')"
        )
        connection.execute(
            "INSERT INTO websocket_tickets("
            "ticket_hash,campaign_id,user_id,credential_kind,bearer_subject,"
            "bearer_jti,bearer_expires_at,created_at,expires_at) VALUES("
            "?,'family-campaign','family-user','bearer','family-user',?,"
            "'2099-01-01T00:00:00.000Z','2030-01-01T00:00:00.000Z',"
            "'2030-01-01T00:00:30.000Z')",
            ("b" * 64, "fixed-jti"),
        )
        connection.commit()
    finally:
        connection.close()


def test_revision_0009_resets_existing_sessions_without_losing_rows(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "upgrade-0009.db"
    _alembic(database_path, command.upgrade, "0008")
    _seed_revision_0008(database_path, legacy_identifier="a" * 64)
    _alembic(database_path, command.upgrade, "0009")

    connection = _connect(database_path)
    try:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        user = connection.execute(
            "SELECT auth_epoch FROM users WHERE id='family-user'"
        ).fetchone()
        refresh = connection.execute(
            "SELECT state,is_revoked,family_id FROM refresh_tokens"
        ).fetchone()
        ticket = connection.execute(
            "SELECT bearer_family_id,bearer_auth_epoch FROM websocket_tickets"
        ).fetchone()
        families = connection.execute(
            "SELECT state,revoke_reason FROM refresh_token_families"
        ).fetchall()
        preserved = (
            revision is not None
            and revision[0] == "0009"
            and user is not None
            and int(user[0]) == 1
            and refresh is not None
            and refresh[0] == "retired"
            and int(refresh[1]) == 1
            and isinstance(refresh[2], str)
            and ticket is not None
            and isinstance(ticket[0], str)
            and int(ticket[1]) == 1
            and len(families) == 2
            and all(
                row[0] == "revoked" and row[1] == "rollout_reset"
                for row in families
            )
        )
    finally:
        connection.close()
    _require(preserved, "revision 0009 did not preserve and reset legacy sessions")


def test_revision_0009_rejects_non_hash_legacy_token_before_advancement(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "unsafe-0009.db"
    _alembic(database_path, command.upgrade, "0008")
    _seed_revision_0008(database_path, legacy_identifier="not-a-hash")
    rejected = False
    try:
        _alembic(database_path, command.upgrade, "0009")
    except RuntimeError:
        rejected = True

    connection = _connect(database_path)
    try:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        family_table = connection.execute(
            "SELECT 1 FROM sqlite_schema "
            "WHERE type='table' AND name='refresh_token_families'"
        ).fetchone()
        user_columns = tuple(
            str(row[1]) for row in connection.execute("PRAGMA table_info(users)")
        )
        original_row = connection.execute(
            "SELECT count(*) FROM refresh_tokens WHERE id='not-a-hash'"
        ).fetchone()
        unchanged = (
            rejected
            and revision is not None
            and revision[0] == "0008"
            and family_table is None
            and "auth_epoch" not in user_columns
            and original_row is not None
            and int(original_row[0]) == 1
        )
    finally:
        connection.close()
    _require(unchanged, "unsafe legacy refresh data mutated during rejection")


def test_revision_0009_constraints_and_forward_only_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "constraints-0009.db"
    _alembic(database_path, command.upgrade, "0009")
    connection = _connect(database_path)
    try:
        connection.execute(
            "INSERT INTO users(id,username,hashed_password,role) "
            "VALUES('constraint-user','constraint-user','fixed','reporter')"
        )
        rejected = False
        try:
            connection.execute(
                "INSERT INTO refresh_token_families("
                "id,user_id,auth_epoch,state,created_at,absolute_expires_at,"
                "revoked_at,revoke_reason,retain_until) VALUES("
                "?,'constraint-user',1,'active',"
                "'2030-01-01T00:00:00.000Z','2030-02-01T00:00:00.000Z',"
                "'2030-01-02T00:00:00.000Z','replay',"
                "'2030-03-01T00:00:00.000Z')",
                ("A" * 43,),
            )
        except sqlite3.IntegrityError:
            rejected = True
        connection.rollback()
    finally:
        connection.close()

    downgrade_rejected = False
    try:
        _alembic(database_path, command.downgrade, "0008")
    except RuntimeError as error:
        downgrade_rejected = str(error) == "revision-0009 downgrade is not supported"
    connection = _connect(database_path)
    try:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    finally:
        connection.close()
    _require(
        rejected
        and downgrade_rejected
        and revision is not None
        and revision[0] == "0009",
        "revision 0009 constraint or forward-only contract changed",
    )
