"""Add authoritative refresh-token families and bearer session authority.

Revision ID: 0009
Revises: 0008
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from datetime import datetime, timedelta, timezone
from importlib import import_module
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_ROLLOUT_REASONS = frozenset(
    {
        "replay",
        "logout_current",
        "logout_all",
        "password_change",
        "password_reset",
        "role_change",
        "user_status_change",
        "rollout_reset",
        "expired",
        "operator_revoke",
    }
)

_PREVIOUS = import_module("migrations.versions.0008_reconcile_schema_parity")
classify_unversioned_catalog = _PREVIOUS.classify_unversioned_catalog
_require_sqlite_alembic_version_relation = (
    _PREVIOUS._require_sqlite_alembic_version_relation
)
_pg_validate_alembic_version_relation = (
    _PREVIOUS._pg_validate_alembic_version_relation
)

_FAMILY_COLUMNS = (
    "id",
    "user_id",
    "auth_epoch",
    "state",
    "created_at",
    "absolute_expires_at",
    "revoked_at",
    "revoke_reason",
    "retain_until",
)
_REFRESH_COLUMNS = (
    "id",
    "user_id",
    "is_revoked",
    "expires_at",
    "created_at",
    "used_at",
    "family_id",
    "parent_id",
    "generation",
    "state",
    "revoked_at",
)
_TICKET_COLUMNS = (
    "ticket_hash",
    "campaign_id",
    "user_id",
    "credential_kind",
    "bearer_subject",
    "bearer_jti",
    "bearer_expires_at",
    "api_key_id",
    "required_scope",
    "created_at",
    "expires_at",
    "consumed_at",
    "bearer_family_id",
    "bearer_auth_epoch",
)


def _fail() -> None:
    raise RuntimeError("revision-0009 preflight failed")


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in {"sqlite", "postgresql"}:
        _fail()
    return name


def _family_id(domain: bytes, value: str) -> str:
    digest = hashlib.sha256(domain + value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_time(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value and value == value.strip():
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            _fail()
    else:
        _fail()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if not math.isfinite(parsed.timestamp()):
        _fail()
    return parsed


def _sqlite_time(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _db_time(value: datetime, dialect: str) -> datetime | str:
    return value if dialect == "postgresql" else _sqlite_time(value)


def _preflight() -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    bind = op.get_bind()
    dialect = _dialect()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    required = {"users", "refresh_tokens", "websocket_tickets", "alembic_version"}
    if not required.issubset(tables) or "refresh_token_families" in tables:
        _fail()

    user_ids = {
        str(row[0])
        for row in bind.execute(sa.text("SELECT id FROM users")).fetchall()
        if isinstance(row[0], str) and row[0]
    }
    refresh_rows: list[dict[str, Any]] = []
    for row in bind.execute(
        sa.text(
            "SELECT id,user_id,is_revoked,expires_at,created_at,used_at "
            "FROM refresh_tokens ORDER BY id"
        )
    ).mappings():
        item = dict(row)
        token_hash = item.get("id")
        user_id = item.get("user_id")
        revoked = item.get("is_revoked")
        if (
            not isinstance(token_hash, str)
            or _HASH_RE.fullmatch(token_hash) is None
            or not isinstance(user_id, str)
            or user_id not in user_ids
            or isinstance(revoked, bool)
            or revoked not in {0, 1}
        ):
            _fail()
        created = _parse_time(item.get("created_at"))
        expires = _parse_time(item.get("expires_at"))
        if expires <= created:
            _fail()
        used_raw = item.get("used_at")
        used = _parse_time(used_raw) if used_raw is not None else None
        if used is not None and used < created:
            _fail()
        item.update(created_at=created, expires_at=expires, used_at=used)
        refresh_rows.append(item)

    bearer_rows: list[dict[str, Any]] = []
    for row in bind.execute(
        sa.text(
            "SELECT ticket_hash,user_id,created_at,expires_at,bearer_expires_at "
            "FROM websocket_tickets WHERE credential_kind='bearer' "
            "ORDER BY ticket_hash"
        )
    ).mappings():
        item = dict(row)
        if (
            not isinstance(item.get("ticket_hash"), str)
            or _HASH_RE.fullmatch(item["ticket_hash"]) is None
            or not isinstance(item.get("user_id"), str)
            or item["user_id"] not in user_ids
        ):
            _fail()
        created = _parse_time(item.get("created_at"))
        expires = _parse_time(item.get("expires_at"))
        bearer_expires = _parse_time(item.get("bearer_expires_at"))
        if expires <= created:
            _fail()
        item.update(
            created_at=created,
            expires_at=expires,
            bearer_expires_at=bearer_expires,
        )
        bearer_rows.append(item)
    return refresh_rows, bearer_rows, dialect


def _timestamp_type(dialect: str) -> sa.types.TypeEngine[Any]:
    return sa.DateTime(timezone=True) if dialect == "postgresql" else sa.Text()


def _family_checks(dialect: str) -> tuple[sa.CheckConstraint, ...]:
    identifier = (
        "id ~ '^[A-Za-z0-9_-]{43}$'"
        if dialect == "postgresql"
        else "length(id)=43 AND id NOT GLOB '*[^A-Za-z0-9_-]*'"
    )
    checks: list[sa.CheckConstraint] = [
        sa.CheckConstraint(identifier, name="ck_refresh_family_id"),
        sa.CheckConstraint("auth_epoch >= 1", name="ck_refresh_family_epoch"),
        sa.CheckConstraint(
            "state IN ('active','revoked')", name="ck_refresh_family_state"
        ),
        sa.CheckConstraint(
            "(state='active' AND revoked_at IS NULL AND revoke_reason IS NULL) OR "
            "(state='revoked' AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)",
            name="ck_refresh_family_revocation_shape",
        ),
        sa.CheckConstraint(
            "revoke_reason IS NULL OR revoke_reason IN ("
            + ",".join(f"'{value}'" for value in sorted(_ROLLOUT_REASONS))
            + ")",
            name="ck_refresh_family_reason",
        ),
    ]
    if dialect == "postgresql":
        checks.extend(
            [
                sa.CheckConstraint(
                    "isfinite(created_at)", name="ck_refresh_family_created_finite"
                ),
                sa.CheckConstraint(
                    "isfinite(absolute_expires_at)",
                    name="ck_refresh_family_expires_finite",
                ),
                sa.CheckConstraint(
                    "revoked_at IS NULL OR isfinite(revoked_at)",
                    name="ck_refresh_family_revoked_finite",
                ),
                sa.CheckConstraint(
                    "isfinite(retain_until)", name="ck_refresh_family_retain_finite"
                ),
            ]
        )
    else:
        for column in (
            "created_at",
            "absolute_expires_at",
            "retain_until",
        ):
            checks.append(
                sa.CheckConstraint(
                    f"strftime('%Y-%m-%dT%H:%M:%fZ',{column}) IS NOT NULL AND "
                    f"strftime('%Y-%m-%dT%H:%M:%fZ',{column})={column}",
                    name=f"ck_refresh_family_{column}_utc",
                )
            )
        checks.append(
            sa.CheckConstraint(
                "revoked_at IS NULL OR "
                "(strftime('%Y-%m-%dT%H:%M:%fZ',revoked_at) IS NOT NULL AND "
                "strftime('%Y-%m-%dT%H:%M:%fZ',revoked_at)=revoked_at)",
                name="ck_refresh_family_revoked_at_utc",
            )
        )
    checks.extend(
        [
            sa.CheckConstraint(
                "absolute_expires_at > created_at",
                name="ck_refresh_family_expiry_order",
            ),
            sa.CheckConstraint(
                "retain_until > absolute_expires_at AND "
                "(revoked_at IS NULL OR retain_until > revoked_at)",
                name="ck_refresh_family_retention_order",
            ),
        ]
    )
    return tuple(checks)


def _create_family_table(dialect: str) -> None:
    timestamp = _timestamp_type(dialect)
    epoch_type: sa.types.TypeEngine[Any] = (
        sa.BigInteger() if dialect == "postgresql" else sa.Integer()
    )
    op.create_table(
        "refresh_token_families",
        sa.Column("id", sa.Text(), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey(
                "users.id", name="fk_refresh_family_user", ondelete="CASCADE"
            ),
            nullable=False,
        ),
        sa.Column("auth_epoch", epoch_type, nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("absolute_expires_at", timestamp, nullable=False),
        sa.Column("revoked_at", timestamp),
        sa.Column("revoke_reason", sa.Text()),
        sa.Column("retain_until", timestamp, nullable=False),
        sa.UniqueConstraint("id", "user_id", name="uq_refresh_family_owner"),
        *_family_checks(dialect),
    )
    op.create_index(
        "idx_refresh_family_user_state_exp",
        "refresh_token_families",
        ["user_id", "state", "absolute_expires_at"],
    )
    op.create_index(
        "idx_refresh_family_retain",
        "refresh_token_families",
        ["retain_until"],
    )


def _add_user_epoch(dialect: str) -> None:
    if dialect == "sqlite":
        op.execute(
            "ALTER TABLE users ADD COLUMN auth_epoch INTEGER NOT NULL "
            "DEFAULT 1 CONSTRAINT ck_users_auth_epoch "
            "CHECK (auth_epoch >= 1)"
        )
        return
    epoch_type: sa.types.TypeEngine[Any] = (
        sa.BigInteger()
    )
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("auth_epoch", epoch_type, nullable=False, server_default="1")
        )
        batch.create_check_constraint("ck_users_auth_epoch", "auth_epoch >= 1")


def _insert_family(
    *,
    family_id: str,
    user_id: str,
    created: datetime,
    expires: datetime,
    revoked: datetime,
    dialect: str,
) -> None:
    retain = max(expires, revoked) + timedelta(days=30)
    op.get_bind().execute(
        sa.text(
            "INSERT INTO refresh_token_families("
            "id,user_id,auth_epoch,state,created_at,absolute_expires_at,"
            "revoked_at,revoke_reason,retain_until) "
            "VALUES(:id,:user_id,1,'revoked',:created,:expires,:revoked,"
            "'rollout_reset',:retain)"
        ),
        {
            "id": family_id,
            "user_id": user_id,
            "created": _db_time(created, dialect),
            "expires": _db_time(expires, dialect),
            "revoked": _db_time(revoked, dialect),
            "retain": _db_time(retain, dialect),
        },
    )


def _upgrade_refresh_tokens(
    rows: list[dict[str, Any]], dialect: str, migration_time: datetime
) -> None:
    epoch_type: sa.types.TypeEngine[Any] = (
        sa.BigInteger() if dialect == "postgresql" else sa.Integer()
    )
    timestamp = _timestamp_type(dialect)
    with op.batch_alter_table("refresh_tokens") as batch:
        batch.add_column(sa.Column("family_id", sa.Text()))
        batch.add_column(sa.Column("parent_id", sa.Text()))
        batch.add_column(sa.Column("generation", epoch_type))
        batch.add_column(sa.Column("state", sa.Text()))
        batch.add_column(sa.Column("revoked_at", timestamp))

    bind = op.get_bind()
    for row in rows:
        family_id = _family_id(b"ARES-0009-LEGACY-REFRESH-V1\0", row["id"])
        _insert_family(
            family_id=family_id,
            user_id=row["user_id"],
            created=row["created_at"],
            expires=row["expires_at"],
            revoked=migration_time,
            dialect=dialect,
        )
        state = "consumed" if row["used_at"] is not None else "retired"
        bind.execute(
            sa.text(
                "UPDATE refresh_tokens SET family_id=:family,generation=0,"
                "state=:state,is_revoked=1,created_at=:created,expires_at=:expires,"
                "used_at=:used,revoked_at=:revoked WHERE id=:token_hash"
            ),
            {
                "family": family_id,
                "state": state,
                "created": _db_time(row["created_at"], dialect),
                "expires": _db_time(row["expires_at"], dialect),
                "used": (
                    _db_time(row["used_at"], dialect)
                    if row["used_at"] is not None
                    else None
                ),
                "revoked": (
                    None if state == "consumed" else _db_time(migration_time, dialect)
                ),
                "token_hash": row["id"],
            },
        )

    hash_check = (
        "id ~ '^[0-9a-f]{64}$'"
        if dialect == "postgresql"
        else "length(id)=64 AND id NOT GLOB '*[^0-9a-f]*'"
    )
    checks: list[tuple[str, str]] = [
        ("ck_refresh_token_hash", hash_check),
        ("ck_refresh_token_generation", "generation >= 0"),
        (
            "ck_refresh_token_parent_shape",
            "(generation=0 AND parent_id IS NULL) OR "
            "(generation>0 AND parent_id IS NOT NULL)",
        ),
        (
            "ck_refresh_token_state",
            "state IN ('active','consumed','retired')",
        ),
        (
            "ck_refresh_token_state_shape",
            "(state='active' AND is_revoked=0 AND used_at IS NULL AND revoked_at IS NULL) OR "
            "(state='consumed' AND is_revoked=1 AND used_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(state='retired' AND is_revoked=1 AND revoked_at IS NOT NULL)",
        ),
        ("ck_refresh_token_expiry_order", "expires_at > created_at"),
    ]
    if dialect == "postgresql":
        checks.append(
            (
                "ck_refresh_token_revoked_finite",
                "revoked_at IS NULL OR isfinite(revoked_at)",
            )
        )
    else:
        checks.extend(
            [
                (
                    "ck_refresh_token_created_utc",
                    "strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND "
                    "strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at",
                ),
                (
                    "ck_refresh_token_expires_utc",
                    "strftime('%Y-%m-%dT%H:%M:%fZ',expires_at) IS NOT NULL AND "
                    "strftime('%Y-%m-%dT%H:%M:%fZ',expires_at)=expires_at",
                ),
                (
                    "ck_refresh_token_used_utc",
                    "used_at IS NULL OR "
                    "(strftime('%Y-%m-%dT%H:%M:%fZ',used_at) IS NOT NULL AND "
                    "strftime('%Y-%m-%dT%H:%M:%fZ',used_at)=used_at)",
                ),
                (
                    "ck_refresh_token_revoked_utc",
                    "revoked_at IS NULL OR "
                    "(strftime('%Y-%m-%dT%H:%M:%fZ',revoked_at) IS NOT NULL AND "
                    "strftime('%Y-%m-%dT%H:%M:%fZ',revoked_at)=revoked_at)",
                ),
            ]
        )

    if dialect == "sqlite":
        op.create_index(
            "uq_refresh_token_family_hash_bootstrap",
            "refresh_tokens",
            ["family_id", "id"],
            unique=True,
        )

    with op.batch_alter_table(
        "refresh_tokens", recreate="always" if dialect == "sqlite" else "auto"
    ) as batch:
        batch.alter_column("family_id", existing_type=sa.Text(), nullable=False)
        batch.alter_column("generation", existing_type=epoch_type, nullable=False)
        batch.alter_column("state", existing_type=sa.Text(), nullable=False)
        batch.create_unique_constraint(
            "uq_refresh_token_family_hash", ["family_id", "id"]
        )
        batch.create_unique_constraint(
            "uq_refresh_token_family_generation", ["family_id", "generation"]
        )
        batch.create_unique_constraint("uq_refresh_token_parent", ["parent_id"])
        batch.create_foreign_key(
            "fk_refresh_token_family_owner",
            "refresh_token_families",
            ["family_id", "user_id"],
            ["id", "user_id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "fk_refresh_token_parent",
            "refresh_tokens",
            ["family_id", "parent_id"],
            ["family_id", "id"],
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        )
        for name, expression in checks:
            batch.create_check_constraint(name, expression)

    if dialect == "sqlite":
        op.drop_index(
            "uq_refresh_token_family_hash_bootstrap",
            table_name="refresh_tokens",
        )

    active_predicate = sa.text("state='active'")
    op.create_index(
        "uq_refresh_token_one_active",
        "refresh_tokens",
        ["family_id"],
        unique=True,
        sqlite_where=active_predicate,
        postgresql_where=active_predicate,
    )
    op.create_index(
        "idx_refresh_family_generation",
        "refresh_tokens",
        ["family_id", "generation"],
    )


_SQLITE_WEBSOCKET_TICKET_TABLE = """
CREATE TABLE websocket_tickets (
    ticket_hash TEXT NOT NULL PRIMARY KEY
        CONSTRAINT ck_ws_ticket_hash CHECK (
            length(ticket_hash)=64
            AND ticket_hash NOT GLOB '*[^0-9a-f]*'
        ),
    campaign_id TEXT NOT NULL CONSTRAINT fk_ws_ticket_campaign
        REFERENCES campaigns(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL CONSTRAINT fk_ws_ticket_user
        REFERENCES users(id) ON DELETE CASCADE,
    credential_kind TEXT NOT NULL CONSTRAINT ck_ws_ticket_kind CHECK (
        credential_kind IN ('bearer', 'api_key')
    ),
    bearer_subject TEXT,
    bearer_jti TEXT,
    bearer_expires_at TEXT,
    api_key_id TEXT CONSTRAINT fk_ws_ticket_api_key
        REFERENCES api_keys(id) ON DELETE CASCADE,
    required_scope TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    bearer_family_id TEXT,
    bearer_auth_epoch INTEGER,
    CONSTRAINT ck_ws_ticket_created_at CHECK (
        strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at)=created_at
    ),
    CONSTRAINT ck_ws_ticket_expires_at CHECK (
        strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at)=expires_at
    ),
    CONSTRAINT ck_ws_ticket_consumed_at CHECK (
        consumed_at IS NULL OR (
            strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) IS NOT NULL
            AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at)=consumed_at
        )
    ),
    CONSTRAINT ck_ws_ticket_time_order CHECK (
        julianday(expires_at) > julianday(created_at)
        AND (
            consumed_at IS NULL
            OR julianday(consumed_at) < julianday(expires_at)
        )
    ),
    CONSTRAINT ck_ws_ticket_source_shape CHECK (
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length(trim(bearer_subject)) > 0
            AND bearer_subject=trim(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length(trim(bearer_jti)) > 0
            AND bearer_jti=trim(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            ) IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            )=bearer_expires_at
            AND bearer_family_id IS NOT NULL
            AND length(bearer_family_id)=43
            AND bearer_family_id NOT GLOB '*[^A-Za-z0-9_-]*'
            AND bearer_auth_epoch IS NOT NULL
            AND typeof(bearer_auth_epoch)='integer'
            AND bearer_auth_epoch >= 1
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND bearer_family_id IS NULL
            AND bearer_auth_epoch IS NULL
            AND api_key_id IS NOT NULL
            AND length(trim(api_key_id)) > 0
            AND api_key_id=trim(api_key_id)
            AND required_scope='read'
        )
    ),
    CONSTRAINT fk_ws_ticket_bearer_family
        FOREIGN KEY (bearer_family_id,user_id)
        REFERENCES refresh_token_families(id,user_id) ON DELETE CASCADE
)
"""

_WEBSOCKET_TICKET_COLUMNS = (
    "ticket_hash",
    "campaign_id",
    "user_id",
    "credential_kind",
    "bearer_subject",
    "bearer_jti",
    "bearer_expires_at",
    "api_key_id",
    "required_scope",
    "created_at",
    "expires_at",
    "consumed_at",
    "bearer_family_id",
    "bearer_auth_epoch",
)
_WEBSOCKET_TICKET_COLUMN_LIST_SQL = ",".join(_WEBSOCKET_TICKET_COLUMNS)
_WEBSOCKET_TICKET_COPY_TO_TEMP_SQL = (  # noqa: S608 - fixed identifiers
    "CREATE TEMP TABLE ares_0009_websocket_ticket_rows AS SELECT "  # noqa: S608
    + _WEBSOCKET_TICKET_COLUMN_LIST_SQL
    + " FROM websocket_tickets"
)
_WEBSOCKET_TICKET_COPY_FROM_TEMP_SQL = (  # noqa: S608 - fixed identifiers
    "INSERT INTO websocket_tickets("  # noqa: S608
    + _WEBSOCKET_TICKET_COLUMN_LIST_SQL
    + ") SELECT "
    + _WEBSOCKET_TICKET_COLUMN_LIST_SQL
    + " FROM ares_0009_websocket_ticket_rows"
)


def _rebuild_sqlite_websocket_tickets() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(_WEBSOCKET_TICKET_COPY_TO_TEMP_SQL))
    bind.execute(sa.text("DROP TABLE websocket_tickets"))
    bind.execute(sa.text(_SQLITE_WEBSOCKET_TICKET_TABLE))
    bind.execute(sa.text(_WEBSOCKET_TICKET_COPY_FROM_TEMP_SQL))
    for name, column in (
        ("idx_ws_tickets_expires", "expires_at"),
        ("idx_ws_tickets_user", "user_id"),
        ("idx_ws_tickets_campaign", "campaign_id"),
        ("idx_ws_tickets_api_key", "api_key_id"),
        ("idx_ws_tickets_bearer_family", "bearer_family_id"),
    ):
        bind.execute(
            sa.text(f"CREATE INDEX {name} ON websocket_tickets({column})")
        )
    bind.execute(sa.text("DROP TABLE ares_0009_websocket_ticket_rows"))


def _upgrade_websocket_tickets(
    rows: list[dict[str, Any]], dialect: str, migration_time: datetime
) -> None:
    epoch_type: sa.types.TypeEngine[Any] = (
        sa.BigInteger() if dialect == "postgresql" else sa.Integer()
    )
    with op.batch_alter_table("websocket_tickets") as batch:
        batch.add_column(sa.Column("bearer_family_id", sa.Text()))
        batch.add_column(sa.Column("bearer_auth_epoch", epoch_type))

    bind = op.get_bind()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["user_id"], []).append(row)
    for user_id, user_rows in grouped.items():
        family_id = _family_id(b"ARES-0009-LEGACY-WS-V1\0", user_id)
        created = min(row["created_at"] for row in user_rows)
        expires = max(
            max(row["expires_at"], row["bearer_expires_at"])
            for row in user_rows
        )
        if expires <= created:
            expires = created + timedelta(seconds=1)
        _insert_family(
            family_id=family_id,
            user_id=user_id,
            created=created,
            expires=expires,
            revoked=migration_time,
            dialect=dialect,
        )
        bind.execute(
            sa.text(
                "UPDATE websocket_tickets SET bearer_family_id=:family,"
                "bearer_auth_epoch=1 WHERE credential_kind='bearer' AND user_id=:user_id"
            ),
            {"family": family_id, "user_id": user_id},
        )

    trim_function = "btrim" if dialect == "postgresql" else "trim"
    epoch_type_guard = (
        "" if dialect == "postgresql" else "AND typeof(bearer_auth_epoch)='integer'"
    )
    bearer_time_guard = (
        ""
        if dialect == "postgresql"
        else """
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            ) IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            )=bearer_expires_at
        """
    )
    source_shape = f"""
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length({trim_function}(bearer_subject)) > 0
            AND bearer_subject={trim_function}(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length({trim_function}(bearer_jti)) > 0
            AND bearer_jti={trim_function}(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            {bearer_time_guard}
            AND bearer_family_id IS NOT NULL
            AND bearer_auth_epoch IS NOT NULL
            {epoch_type_guard}
            AND bearer_auth_epoch >= 1
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND bearer_family_id IS NULL
            AND bearer_auth_epoch IS NULL
            AND api_key_id IS NOT NULL
            AND length({trim_function}(api_key_id)) > 0
            AND api_key_id={trim_function}(api_key_id)
            AND required_scope='read'
        )
    """
    if dialect == "sqlite":
        _rebuild_sqlite_websocket_tickets()
        return
    with op.batch_alter_table(
        "websocket_tickets", recreate="always" if dialect == "sqlite" else "auto"
    ) as batch:
        batch.drop_constraint("ck_ws_ticket_source_shape", type_="check")
        batch.create_check_constraint("ck_ws_ticket_source_shape", source_shape)
        batch.create_foreign_key(
            "fk_ws_ticket_bearer_family",
            "refresh_token_families",
            ["bearer_family_id", "user_id"],
            ["id", "user_id"],
            ondelete="CASCADE",
        )
    op.create_index(
        "idx_ws_tickets_bearer_family",
        "websocket_tickets",
        ["bearer_family_id"],
    )


def _column_names(inspector: sa.Inspector, table: str) -> tuple[str, ...]:
    return tuple(str(item["name"]) for item in inspector.get_columns(table))


def verify_managed_catalog(bind: Any) -> None:
    """Verify the revision-0009 additions on the canonical revision-0008 set."""
    dialect = bind.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        _fail()
    if dialect == "sqlite":
        _require_sqlite_alembic_version_relation(bind, "0009")
        expected_tables = set(_PREVIOUS._SQLITE_COLUMNS) | {
            "alembic_version",
            "refresh_token_families",
        }
    else:
        _pg_validate_alembic_version_relation(bind, "0009")
        expected_tables = set(
            _PREVIOUS._PG_REQUIRED_TABLES | _PREVIOUS._PG_OPTIONAL_TABLES
        ) | {"alembic_version", "refresh_token_families"}
        relation_rows = bind.execute(
            sa.text(
                """
                SELECT relation.relname, relation.relkind::text
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname=current_schema()
                  AND relation.relname=ANY(:names)
                """
            ),
            {
                "names": sorted(
                    expected_tables
                    | {"audit_log_id_seq", "rate_limit_events_id_seq"}
                )
            },
        ).fetchall()
        expected_relations = {(name, "r") for name in expected_tables}
        expected_relations.update(
            {
                ("audit_log_id_seq", "S"),
                ("rate_limit_events_id_seq", "S"),
            }
        )
        if {
            (str(row[0]), str(row[1])) for row in relation_rows
        } != expected_relations:
            _fail()
    inspector = sa.inspect(bind)
    actual_tables = set(inspector.get_table_names())
    if (
        dialect == "sqlite" and actual_tables != expected_tables
    ) or (
        dialect == "postgresql"
        and not expected_tables.issubset(actual_tables)
    ):
        _fail()
    if _column_names(inspector, "refresh_token_families") != _FAMILY_COLUMNS:
        _fail()
    if _column_names(inspector, "refresh_tokens") != _REFRESH_COLUMNS:
        _fail()
    if _column_names(inspector, "websocket_tickets") != _TICKET_COLUMNS:
        _fail()
    user_columns = _column_names(inspector, "users")
    if user_columns[-1:] != ("auth_epoch",) or user_columns.count(
        "auth_epoch"
    ) != 1:
        _fail()
    family_indexes = {
        str(item["name"]): (
            tuple(str(value) for value in item["column_names"]),
            bool(item["unique"]),
        )
        for item in inspector.get_indexes("refresh_token_families")
        if item.get("duplicates_constraint") is None
    }
    required_family_indexes = {
        "idx_refresh_family_user_state_exp": (
            ("user_id", "state", "absolute_expires_at"),
            False,
        ),
        "idx_refresh_family_retain": (("retain_until",), False),
    }
    if family_indexes != required_family_indexes:
        _fail()
    refresh_indexes = {
        str(item["name"]): tuple(
            str(value) for value in item["column_names"]
        )
        for item in inspector.get_indexes("refresh_tokens")
    }
    if refresh_indexes.get("uq_refresh_token_one_active") != ("family_id",):
        _fail()
    if refresh_indexes.get("idx_refresh_family_generation") != (
        "family_id",
        "generation",
    ):
        _fail()
    ticket_indexes = {
        str(item["name"]): tuple(
            str(value) for value in item["column_names"]
        )
        for item in inspector.get_indexes("websocket_tickets")
    }
    if ticket_indexes.get("idx_ws_tickets_bearer_family") != (
        "bearer_family_id",
    ):
        _fail()


def upgrade() -> None:
    refresh_rows, bearer_rows, dialect = _preflight()
    migration_time = datetime.now(timezone.utc)
    _add_user_epoch(dialect)
    _create_family_table(dialect)
    _upgrade_refresh_tokens(refresh_rows, dialect, migration_time)
    _upgrade_websocket_tickets(bearer_rows, dialect, migration_time)


def downgrade() -> None:
    raise RuntimeError("revision-0009 downgrade is not supported")
