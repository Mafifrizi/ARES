"""
ARES Database — PostgreSQL async backend via asyncpg.

Used when ARES_DATABASE_URL starts with postgresql+asyncpg:// or postgresql://.

Install:
    pip install ares-redteam[postgres]      # adds asyncpg>=0.29
    # or:
    pip install asyncpg

Configuration (.env):
    ARES_DATABASE_URL=postgresql+asyncpg://ares_user:strong_password@db:5432/ares_db
    ARES_ENCRYPTION_KEY=<fernet-key>

Design:
  - Same public API as AresDatabase (SQLite) — zero changes to server.py or engine.py
  - asyncpg connection pool (min=2, max=10)
  - All credential/token content encrypted at rest via Fernet (same as SQLite backend)
  - Alembic-managed migrations: `alembic -x db_url=<url> upgrade head`
  - Parameterized queries throughout — no string interpolation

Production checklist:
  □ Create ares_user with CREATEDB privilege or pre-create ares_db
  □ Set ARES_DATABASE_URL in .env (never commit)
  □ Run alembic upgrade head before first start
  □ Set max_connections in postgresql.conf to > (max_workers × pool_max + 5)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from ares.core.logger import get_logger
from ares.core.security import DataEncryptor, hash_password, verify_password
from ares.db.websocket_tickets import (
    ApiKeyTicketSource,
    BearerTicketSource,
    ConsumedWebSocketTicket,
    WebSocketTicketCredentialKind,
    WebSocketTicketPrincipal,
    WEBSOCKET_TICKET_TTL_SECONDS,
    generate_websocket_ticket,
    hash_websocket_ticket,
    is_canonical_websocket_ticket,
    is_valid_websocket_principal_role,
    normalize_api_key_scopes,
)

logger = get_logger("ares.db.postgres")

_REFRESH_TOKEN_LOCK_NAMESPACE = b"ares:refresh-token-user:v1\x00"


def _refresh_token_user_lock_key(user_id: str) -> int:
    """Return a stable signed BIGINT key for a user's refresh-token writes."""
    digest = hashlib.sha256(
        _REFRESH_TOKEN_LOCK_NAMESPACE + user_id.encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


async def _acquire_refresh_token_user_lock(conn: Any, user_id: str) -> None:
    await conn.execute(
        "SELECT pg_advisory_xact_lock($1::BIGINT)",
        _refresh_token_user_lock_key(user_id),
    )


def _parse_postgres_timestamptz(value: str) -> datetime:
    """Convert the public access-token expiry string to an aware datetime."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    return parsed.astimezone(timezone.utc)


# ── Postgres schema DDL ────────────────────────────────────────────────────────
# Equivalent to schema.py but for PostgreSQL syntax.
# Alembic handles migrations; this DDL is the "create if not exists" fallback.

_PG_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS campaigns (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    client          TEXT NOT NULL DEFAULT 'Internal',
    operator        TEXT NOT NULL DEFAULT 'unknown',
    noise_profile   TEXT NOT NULL DEFAULT 'stealth',
    status          TEXT NOT NULL DEFAULT 'created',
    scope_json      TEXT NOT NULL DEFAULT '[]',
    targets_json    TEXT NOT NULL DEFAULT '[]',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS module_runs (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    success         INTEGER NOT NULL DEFAULT 0,
    duration_ms     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    completed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_module_runs_campaign ON module_runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_module_runs_completed ON module_runs(completed_at);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      FLOAT NOT NULL DEFAULT 1.0,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    cvss_score      FLOAT NOT NULL DEFAULT 0.0,
    cvss_vector     TEXT NOT NULL DEFAULT '',
    trace_id        TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    remediation     TEXT DEFAULT '',
    host            TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_findings_campaign  ON findings(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_pg_findings_fp        ON findings(false_positive);

CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    fqdn            TEXT,
    os              TEXT,
    os_version      TEXT,
    domain          TEXT,
    is_dc           INTEGER NOT NULL DEFAULT 0,
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    tags_json       TEXT NOT NULL DEFAULT '[]',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(campaign_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_pg_hosts_campaign ON hosts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_hosts_ip       ON hosts(ip_address);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    host_id         TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    username        TEXT NOT NULL,
    secret_enc      TEXT,
    cred_type       TEXT NOT NULL,
    domain          TEXT,
    source_module   TEXT,
    notes           TEXT DEFAULT '',
    cracked         INTEGER NOT NULL DEFAULT 0,
    cracked_value_enc TEXT,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_creds_campaign ON credentials(campaign_id);

CREATE TABLE IF NOT EXISTS loot (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    host_id         TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    loot_type       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    content_enc     TEXT,
    size_bytes      INTEGER DEFAULT 0,
    path_on_target  TEXT,
    source_module   TEXT,
    tags_json       TEXT NOT NULL DEFAULT '[]',
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    actor           TEXT NOT NULL DEFAULT 'system',
    action          TEXT NOT NULL,
    detail          TEXT DEFAULT '',
    module_id       TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_audit_campaign ON audit_log(campaign_id);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'reporter',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_users_username ON users(username);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT 'read',
    is_active   INTEGER NOT NULL DEFAULT 1,
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_apikeys_user   ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_pg_apikeys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_revoked  INTEGER NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pg_refresh_exp  ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_rat_expires ON revoked_access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS websocket_tickets (
    ticket_hash       TEXT NOT NULL PRIMARY KEY
                      CONSTRAINT ck_ws_ticket_hash CHECK (
                          ticket_hash ~ '^[0-9a-f]{64}$'
                      ),
    campaign_id       TEXT NOT NULL
                      CONSTRAINT fk_ws_ticket_campaign
                      REFERENCES campaigns(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL
                      CONSTRAINT fk_ws_ticket_user
                      REFERENCES users(id) ON DELETE CASCADE,
    credential_kind   TEXT NOT NULL
                      CONSTRAINT ck_ws_ticket_kind CHECK (
                          credential_kind IN ('bearer', 'api_key')
                      ),
    bearer_subject    TEXT,
    bearer_jti        TEXT,
    bearer_expires_at TIMESTAMPTZ,
    api_key_id        TEXT
                      CONSTRAINT fk_ws_ticket_api_key
                      REFERENCES api_keys(id) ON DELETE CASCADE,
    required_scope    TEXT,
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    CONSTRAINT ck_ws_ticket_created_at CHECK (created_at < expires_at),
    CONSTRAINT ck_ws_ticket_expires_at CHECK (expires_at > created_at),
    CONSTRAINT ck_ws_ticket_consumed_at CHECK (
        consumed_at IS NULL OR consumed_at < expires_at
    ),
    CONSTRAINT ck_ws_ticket_bearer_expires_finite CHECK (
        bearer_expires_at IS NULL OR isfinite(bearer_expires_at)
    ),
    CONSTRAINT ck_ws_ticket_created_finite CHECK (isfinite(created_at)),
    CONSTRAINT ck_ws_ticket_expires_finite CHECK (isfinite(expires_at)),
    CONSTRAINT ck_ws_ticket_consumed_finite CHECK (
        consumed_at IS NULL OR isfinite(consumed_at)
    ),
    CONSTRAINT ck_ws_ticket_time_order CHECK (
        expires_at > created_at
        AND (consumed_at IS NULL OR consumed_at < expires_at)
    ),
    CONSTRAINT ck_ws_ticket_source_shape CHECK (
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length(btrim(bearer_subject)) > 0
            AND bearer_subject=btrim(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length(btrim(bearer_jti)) > 0
            AND bearer_jti=btrim(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND api_key_id IS NOT NULL
            AND length(btrim(api_key_id)) > 0
            AND api_key_id=btrim(api_key_id)
            AND required_scope='read'
        )
    )
);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_expires
    ON websocket_tickets(expires_at);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_user
    ON websocket_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_campaign
    ON websocket_tickets(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_api_key
    ON websocket_tickets(api_key_id);
"""

_POSTGRES_MANAGED_REVISION = "0008"
_POSTGRES_OLDER_REVISIONS = frozenset(
    {"0001", "0002", "0003", "0004", "0005", "0006", "0007"}
)
_POSTGRES_MIGRATION_REQUIRED_ERROR = "PostgreSQL schema migration required"
_POSTGRES_MANAGED_SCHEMA_ERROR = "Incompatible managed PostgreSQL schema"
_POSTGRES_SCHEMA_VALIDATION_ERROR = "PostgreSQL schema validation failed"


class _PostgresMigrationRequiredError(RuntimeError):
    pass


class _PostgresManagedSchemaError(RuntimeError):
    pass


_POSTGRES_MANAGED_TABLES = frozenset(
    {
        "campaigns",
        "module_runs",
        "findings",
        "hosts",
        "credentials",
        "loot",
        "audit_log",
        "users",
        "api_keys",
        "refresh_tokens",
        "revoked_access_tokens",
        "rate_limit_events",
        "websocket_tickets",
    }
)

_POSTGRES_MANAGED_INDEXES = (
    ("module_runs", "idx_module_runs_campaign", ("campaign_id",)),
    ("module_runs", "idx_module_runs_completed", ("completed_at",)),
    ("findings", "idx_findings_campaign", ("campaign_id",)),
    ("findings", "idx_findings_severity", ("severity",)),
    ("findings", "idx_findings_fp", ("false_positive",)),
    ("findings", "idx_findings_mitre", ("mitre_technique",)),
    ("findings", "idx_findings_cvss", ("cvss_score",)),
    ("hosts", "idx_hosts_campaign", ("campaign_id",)),
    ("hosts", "idx_hosts_ip", ("ip_address",)),
    ("hosts", "idx_hosts_domain", ("domain",)),
    ("credentials", "idx_creds_campaign", ("campaign_id",)),
    ("credentials", "idx_creds_username", ("username",)),
    ("credentials", "idx_creds_type", ("cred_type",)),
    ("loot", "idx_loot_campaign", ("campaign_id",)),
    ("loot", "idx_loot_type", ("loot_type",)),
    ("audit_log", "idx_audit_campaign", ("campaign_id",)),
    ("audit_log", "idx_audit_actor", ("actor",)),
    ("audit_log", "idx_audit_action", ("action",)),
    ("users", "idx_users_username", ("username",)),
    ("users", "idx_users_role", ("role",)),
    ("api_keys", "idx_apikeys_user", ("user_id",)),
    ("api_keys", "idx_apikeys_prefix", ("key_prefix",)),
    ("refresh_tokens", "idx_refresh_user", ("user_id",)),
    ("refresh_tokens", "idx_refresh_exp", ("expires_at",)),
    ("revoked_access_tokens", "idx_rat_expires", ("expires_at",)),
    ("rate_limit_events", "idx_rle_ip", ("ip_address",)),
    ("rate_limit_events", "idx_rle_timestamp", ("timestamp",)),
    ("rate_limit_events", "idx_rle_blocked", ("blocked",)),
)

_POSTGRES_MANAGED_PRIMARY_KEYS = (
    ("campaigns", "campaigns_pkey", ("id",)),
    ("module_runs", "module_runs_pkey", ("id",)),
    ("findings", "findings_pkey", ("id",)),
    ("hosts", "hosts_pkey", ("id",)),
    ("credentials", "credentials_pkey", ("id",)),
    ("loot", "loot_pkey", ("id",)),
    ("audit_log", "audit_log_pkey", ("id",)),
    ("users", "users_pkey", ("id",)),
    ("api_keys", "api_keys_pkey", ("id",)),
    ("refresh_tokens", "refresh_tokens_pkey", ("id",)),
    (
        "revoked_access_tokens",
        "revoked_access_tokens_pkey",
        ("jti",),
    ),
    ("rate_limit_events", "rate_limit_events_pkey", ("id",)),
)

_POSTGRES_MANAGED_FOREIGN_KEYS = (
    (
        "module_runs",
        "fk_module_runs_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "findings",
        "fk_findings_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "hosts",
        "fk_hosts_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "credentials",
        "fk_credentials_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "credentials",
        "fk_credentials_host",
        ("host_id",),
        "hosts",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "loot",
        "fk_loot_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "loot",
        "fk_loot_host",
        ("host_id",),
        "hosts",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "audit_log",
        "fk_audit_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "api_keys",
        "fk_api_keys_user",
        ("user_id",),
        "users",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "refresh_tokens",
        "fk_refresh_tokens_user",
        ("user_id",),
        "users",
        ("id",),
        "CASCADE",
        "c",
    ),
)

_POSTGRES_MANAGED_UNIQUES = (
    ("hosts", "uq_hosts_campaign_ip", ("campaign_id", "ip_address")),
    ("users", "uq_users_username", ("username",)),
)

_POSTGRES_MANAGED_FINITE_CHECKS = (
    ("campaigns", "created_at", False),
    ("campaigns", "updated_at", False),
    ("module_runs", "completed_at", False),
    ("findings", "discovered_at", False),
    ("hosts", "first_seen", False),
    ("hosts", "last_seen", False),
    ("credentials", "captured_at", False),
    ("loot", "captured_at", False),
    ("audit_log", "timestamp", False),
    ("users", "created_at", False),
    ("users", "last_login", True),
    ("api_keys", "last_used", True),
    ("api_keys", "expires_at", True),
    ("api_keys", "created_at", False),
    ("refresh_tokens", "expires_at", False),
    ("refresh_tokens", "created_at", False),
    ("refresh_tokens", "used_at", True),
    ("rate_limit_events", "timestamp", False),
    ("revoked_access_tokens", "revoked_at", False),
    ("revoked_access_tokens", "expires_at", False),
)


def _postgres_finite_check_name(table: str, column: str) -> str:
    if table == "module_runs":
        return "ck_module_runs_completed_at_finite"
    if table == "audit_log":
        return "ck_audit_log_timestamp_finite"
    if table == "rate_limit_events":
        return "ck_rate_limit_events_timestamp_finite"
    return f"ck_{table}_{column}_finite"


def _postgres_constraint_definition(value: object) -> str:
    return " ".join(str(value).split())


def _postgres_index_opclass(table: str, column: str) -> str:
    if (table, column) in {
        ("findings", "false_positive"),
        ("rate_limit_events", "blocked"),
    }:
        return "int4_ops"
    if (table, column) == ("findings", "cvss_score"):
        return "float8_ops"
    if (table, column) in {
        ("module_runs", "completed_at"),
        ("refresh_tokens", "expires_at"),
        ("revoked_access_tokens", "expires_at"),
        ("rate_limit_events", "timestamp"),
    }:
        return "timestamptz_ops"
    return "text_ops"


def _classify_postgres_revision(values: tuple[object, ...]) -> str:
    if len(values) != 1 or not isinstance(values[0], str):
        raise _PostgresManagedSchemaError(_POSTGRES_MANAGED_SCHEMA_ERROR)
    revision = values[0]
    if revision == _POSTGRES_MANAGED_REVISION:
        return revision
    if revision in _POSTGRES_OLDER_REVISIONS:
        raise _PostgresMigrationRequiredError(
            _POSTGRES_MIGRATION_REQUIRED_ERROR
        )
    raise _PostgresManagedSchemaError(_POSTGRES_MANAGED_SCHEMA_ERROR)


class PostgresDatabase:
    """
    Async PostgreSQL database backend via asyncpg.
    Public API is identical to AresDatabase (SQLite) — drop-in replacement.

    Usage:
        db = await PostgresDatabase.create(
            dsn            = "postgresql+asyncpg://user:pass@host/db",
            encryption_key = settings.encryption_key_value,
        )
        app.state.db = db
    """

    def __init__(
        self,
        dsn:            str,
        encryption_key: str | None = None,
        pool_min:       int = 2,
        pool_max:       int = 10,
    ) -> None:
        # Strip SQLAlchemy dialect prefix — asyncpg uses plain postgres:// DSN
        self._dsn = (
            dsn
            .replace("postgresql+asyncpg://", "postgresql://")
            .replace("postgres+asyncpg://",   "postgres://")
        )
        self._enc: DataEncryptor | None = DataEncryptor(encryption_key) if encryption_key else None
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: Any = None   # asyncpg.Pool

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def connect(self) -> "PostgresDatabase":
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "asyncpg is required for PostgreSQL support. "
                "Install: pip install ares-redteam[postgres]"
            ) from exc
        pool = await asyncpg.create_pool(
            self._dsn,
            min_size=self._pool_min,
            max_size=self._pool_max,
            command_timeout=30,
        )
        self._pool = pool
        try:
            await self._init_schema()
        except Exception as primary:
            await self._close_failed_startup_pool(pool, primary)
            raise
        except asyncio.CancelledError as primary:
            await self._close_failed_startup_pool(pool, primary)
            raise
        logger.info("pg_db_ready")
        return self

    async def _close_failed_startup_pool(
        self,
        pool: Any,
        primary: BaseException,
    ) -> None:
        try:
            await pool.close()
        except Exception as cleanup_error:
            primary.add_note(
                "PostgreSQL startup cleanup failure "
                f"[pool-close: {type(cleanup_error).__name__}]"
            )
        finally:
            if self._pool is pool:
                self._pool = None

    async def __aenter__(self) -> "PostgresDatabase":
        return await self.connect()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @classmethod
    async def create(
        cls,
        dsn:            str,
        encryption_key: str | None = None,
    ) -> "PostgresDatabase":
        db = cls(dsn, encryption_key)
        return await db.connect()

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    @staticmethod
    async def _managed_schema_revision(connection: Any) -> str | None:
        relation_rows = await connection.fetch(
            """
            SELECT rel.oid::bigint AS table_oid,
                   nsp.nspname AS schema_name,
                   relation_type.oid::bigint AS type_oid,
                   type_nsp.nspname AS type_schema,
                   relation_type.typname AS type_name,
                   relation_type.typtype,
                   relation_type.typrelid::bigint AS type_relation_oid,
                   rel.relkind,
                   rel.relpersistence,
                   rel.relispartition,
                   rel.relrowsecurity,
                   rel.relforcerowsecurity,
                   (
                       SELECT count(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhrelid=rel.oid
                   ) AS parent_count,
                   (
                       SELECT count(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhparent=rel.oid
                   ) AS child_count,
                   (
                       SELECT count(*)
                       FROM pg_policy AS policy
                       WHERE policy.polrelid=rel.oid
                   ) AS policy_count,
                   (
                       SELECT count(*)
                       FROM pg_trigger AS trigger_record
                       WHERE trigger_record.tgrelid=rel.oid
                         AND NOT trigger_record.tgisinternal
                   ) AS user_trigger_count,
                   (
                       SELECT count(*)
                       FROM pg_rewrite AS rewrite
                       WHERE rewrite.ev_class=rel.oid
                   ) AS user_rule_count
            FROM pg_class AS rel
            JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
            LEFT JOIN pg_type AS relation_type
              ON relation_type.oid=rel.reltype
            LEFT JOIN pg_namespace AS type_nsp
              ON type_nsp.oid=relation_type.typnamespace
            WHERE nsp.nspname=current_schema()
              AND rel.relname='alembic_version'
            """
        )
        if not relation_rows:
            return None
        if len(relation_rows) != 1:
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
        relation = relation_rows[0]
        try:
            table_oid = int(relation["table_oid"])
            schema_name = relation["schema_name"]
            type_oid = int(relation["type_oid"])
            type_contract = (
                relation["type_schema"],
                relation["type_name"],
                str(relation["typtype"]),
                int(relation["type_relation_oid"]),
            )
            relation_contract = (
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
             )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        if (
            not isinstance(schema_name, str)
            or not schema_name
            or type_oid <= 0
            or type_contract
            != (schema_name, "alembic_version", "c", table_oid)
            or relation_contract
            != ("r", "p", False, False, False, 0, 0, 0, 0, 0)
        ):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        column_rows = await connection.fetch(
            """
            SELECT att.attnum,
                   att.attname AS column_name,
                   pg_catalog.format_type(
                       att.atttypid,
                       att.atttypmod
                   ) AS data_type,
                   att.attnotnull,
                   att.attidentity,
                   att.attgenerated,
                   att.attisdropped,
                   att.attinhcount,
                   att.attislocal,
                   att.atthasmissing,
                   att.attmissingval::text AS missing_value,
                   att.attcollation=type_record.typcollation
                       AS collation_is_default,
                   pg_get_expr(def.adbin, def.adrelid) AS column_default
            FROM pg_attribute AS att
            LEFT JOIN pg_type AS type_record
              ON type_record.oid=att.atttypid
            LEFT JOIN pg_attrdef AS def
              ON def.adrelid=att.attrelid
             AND def.adnum=att.attnum
            WHERE att.attrelid=$1::oid
              AND att.attnum > 0
            ORDER BY att.attnum
            """,
            table_oid,
        )
        try:
            columns = tuple(
                (
                    int(row["attnum"]),
                    str(row["column_name"]),
                    str(row["data_type"]),
                    bool(row["attnotnull"]),
                    str(row["attidentity"]),
                    str(row["attgenerated"]),
                    bool(row["attisdropped"]),
                    int(row["attinhcount"]),
                    bool(row["attislocal"]),
                    bool(row["atthasmissing"]),
                    row["missing_value"],
                    bool(row["collation_is_default"]),
                    row["column_default"],
                )
                for row in column_rows
            )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        if columns != (
            (
                1,
                "version_num",
                "character varying(32)",
                True,
                "",
                "",
                False,
                0,
                True,
                False,
                None,
                True,
                None,
            ),
        ):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        primary_rows = await connection.fetch(
            """
            SELECT con.conname,
                   con.contype,
                   con.convalidated,
                   con.condeferrable,
                   con.condeferred,
                   ARRAY(
                       SELECT att.attname
                       FROM unnest(con.conkey)
                            WITH ORDINALITY AS key(attnum, position)
                       JOIN pg_attribute AS att
                         ON att.attrelid=con.conrelid
                        AND att.attnum=key.attnum
                       ORDER BY key.position
                   ) AS columns
            FROM pg_constraint AS con
            WHERE con.conrelid=$1::oid
            ORDER BY con.conname
            """,
            table_oid,
        )
        try:
            primary_contract = tuple(
                (
                    str(row["conname"]),
                    str(row["contype"]),
                    bool(row["convalidated"]),
                    bool(row["condeferrable"]),
                    bool(row["condeferred"]),
                    tuple(str(column) for column in row["columns"]),
                )
                for row in primary_rows
            )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        if primary_contract != (
            (
                "alembic_version_pkc",
                "p",
                True,
                False,
                False,
                ("version_num",),
            ),
        ):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        version_index_rows = await connection.fetch(
            """
            SELECT index_rel.relname AS index_name,
                   index_rel.relkind AS index_relkind,
                   index_rel.relpersistence AS index_relpersistence,
                   index_rel.relispartition AS index_is_partition,
                   access_method.amname AS access_method,
                   ind.indisunique,
                   ind.indisprimary,
                   ind.indisvalid,
                   ind.indisready,
                   ind.indislive,
                   ind.indnkeyatts,
                   ind.indnatts,
                   con.conname AS constraint_name,
                   ARRAY(
                       SELECT att.attname
                       FROM unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY key.position
                   ) AS columns,
                   ARRAY(
                       SELECT option
                       FROM unnest(ind.indoption)
                            WITH ORDINALITY AS item(option, position)
                       ORDER BY item.position
                   ) AS column_options,
                   ARRAY(
                       SELECT opc.opcname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       ORDER BY item.position
                   ) AS operator_classes,
                   ARRAY(
                       SELECT opc_nsp.nspname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       JOIN pg_namespace AS opc_nsp
                         ON opc_nsp.oid=opc.opcnamespace
                       ORDER BY item.position
                   ) AS operator_class_namespaces,
                   ARRAY(
                       SELECT item.collation=att.attcollation
                       FROM unnest(ind.indcollation)
                            WITH ORDINALITY AS item(collation, position)
                       JOIN unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                         ON key.position=item.position
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY item.position
                   ) AS column_collations_match,
                   pg_get_expr(ind.indexprs, ind.indrelid) AS expressions,
                   pg_get_expr(ind.indpred, ind.indrelid) AS predicate
            FROM pg_index AS ind
            JOIN pg_class AS index_rel ON index_rel.oid=ind.indexrelid
            JOIN pg_am AS access_method ON access_method.oid=index_rel.relam
            LEFT JOIN pg_constraint AS con
              ON con.conindid=ind.indexrelid
            WHERE ind.indrelid=$1::oid
            ORDER BY index_rel.relname
            """,
            table_oid,
        )
        try:
            version_indexes = tuple(
                (
                    str(row["index_name"]),
                    str(row["index_relkind"]),
                    str(row["index_relpersistence"]),
                    bool(row["index_is_partition"]),
                    str(row["access_method"]),
                    bool(row["indisunique"]),
                    bool(row["indisprimary"]),
                    bool(row["indisvalid"]),
                    bool(row["indisready"]),
                    bool(row["indislive"]),
                    int(row["indnkeyatts"]),
                    int(row["indnatts"]),
                    row["constraint_name"],
                    tuple(str(column) for column in row["columns"]),
                    tuple(int(option) for option in row["column_options"]),
                    tuple(
                        str(opclass) for opclass in row["operator_classes"]
                    ),
                    tuple(
                        str(namespace)
                        for namespace in row["operator_class_namespaces"]
                    ),
                    tuple(
                        bool(value)
                        for value in row["column_collations_match"]
                    ),
                    row["expressions"],
                    row["predicate"],
                )
                for row in version_index_rows
            )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        if version_indexes != (
            (
                "alembic_version_pkc",
                "i",
                "p",
                False,
                "btree",
                True,
                True,
                True,
                True,
                True,
                1,
                1,
                "alembic_version_pkc",
                ("version_num",),
                (0,),
                ("text_ops",),
                ("pg_catalog",),
                (True,),
                None,
                None,
            ),
        ):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        quoted_schema = '"' + schema_name.replace('"', '""') + '"'
        revision_rows = await connection.fetch(
            f'SELECT version_num FROM {quoted_schema}."alembic_version"'  # noqa: S608
        )
        try:
            values = tuple(row["version_num"] for row in revision_rows)
        except (KeyError, TypeError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        return _classify_postgres_revision(values)

    @staticmethod
    async def _validate_managed_schema(connection: Any) -> None:
        table_rows = await connection.fetch(
            """
            SELECT rel.oid::bigint AS table_oid,
                   rel.relname AS table_name,
                   nsp.nspname AS table_schema,
                   relation_type.oid::bigint AS type_oid,
                   type_nsp.nspname AS type_schema,
                   relation_type.typname AS type_name,
                   relation_type.typtype,
                   relation_type.typrelid::bigint AS type_relation_oid,
                   rel.relkind,
                   rel.relpersistence,
                   rel.relispartition,
                   rel.relrowsecurity,
                   rel.relforcerowsecurity,
                   (
                       SELECT count(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhrelid=rel.oid
                   ) AS parent_count,
                   (
                       SELECT count(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhparent=rel.oid
                   ) AS child_count,
                   (
                       SELECT count(*)
                       FROM pg_policy AS policy
                       WHERE policy.polrelid=rel.oid
                   ) AS policy_count,
                   (
                       SELECT count(*)
                       FROM pg_trigger AS trigger_record
                       WHERE trigger_record.tgrelid=rel.oid
                         AND NOT trigger_record.tgisinternal
                   ) AS user_trigger_count,
                   (
                       SELECT count(*)
                       FROM pg_rewrite AS rewrite
                       WHERE rewrite.ev_class=rel.oid
                   ) AS user_rule_count
            FROM pg_class AS rel
            JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
            JOIN pg_type AS relation_type ON relation_type.oid=rel.reltype
            JOIN pg_namespace AS type_nsp
              ON type_nsp.oid=relation_type.typnamespace
            WHERE nsp.nspname=current_schema()
              AND rel.relname=ANY($1::text[])
            ORDER BY rel.relname
            """,
            sorted(_POSTGRES_MANAGED_TABLES),
        )
        try:
            table_contract = {
                str(row["table_name"]): (
                    int(row["table_oid"]),
                    str(row["relkind"]),
                    str(row["relpersistence"]),
                    bool(row["relispartition"]),
                    bool(row["relrowsecurity"]),
                    bool(row["relforcerowsecurity"]),
                    int(row["parent_count"]),
                    int(row["child_count"]),
                    int(row["policy_count"]),
                    int(row["user_trigger_count"]),
                    int(row["user_rule_count"]),
                    str(row["table_schema"]),
                    int(row["type_oid"]),
                    str(row["type_schema"]),
                    str(row["type_name"]),
                    str(row["typtype"]),
                    int(row["type_relation_oid"]),
                )
                for row in table_rows
            }
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        if set(table_contract) != _POSTGRES_MANAGED_TABLES:
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
        for table, metadata in table_contract.items():
            expected = (
                ("r", "p", False)
                if table == "websocket_tickets"
                else (
                    "r",
                    "p",
                    False,
                    False,
                    False,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            )
            actual = (
                metadata[1:4]
                if table == "websocket_tickets"
                else metadata[1:11]
            )
            (
                table_schema,
                type_oid,
                type_schema,
                type_name,
                type_kind,
                type_relation_oid,
            ) = metadata[11:]
            if (
                actual != expected
                or not table_schema
                or type_oid <= 0
                or type_schema != table_schema
                or type_name != table
                or type_kind != "c"
                or type_relation_oid != metadata[0]
            ):
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        non_ticket_tables = sorted(
            _POSTGRES_MANAGED_TABLES - {"websocket_tickets"}
        )
        legacy_index_rows = await connection.fetch(
            """
            SELECT table_rel.relname AS table_name,
                   index_rel.relname AS index_name
            FROM pg_index AS ind
            JOIN pg_class AS table_rel ON table_rel.oid=ind.indrelid
            JOIN pg_namespace AS table_nsp
              ON table_nsp.oid=table_rel.relnamespace
            JOIN pg_class AS index_rel ON index_rel.oid=ind.indexrelid
            WHERE table_nsp.nspname=current_schema()
              AND table_rel.relname=ANY($1::text[])
              AND left(index_rel.relname, 7)='idx_pg_'
            ORDER BY table_rel.relname, index_rel.relname
            """,
            sorted(_POSTGRES_MANAGED_TABLES),
        )
        if legacy_index_rows:
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        index_rows = await connection.fetch(
            """
            SELECT table_rel.relname AS table_name,
                   index_rel.relname AS index_name,
                   index_rel.relkind AS index_relkind,
                   index_rel.relpersistence AS index_relpersistence,
                   index_rel.relispartition AS index_is_partition,
                   access_method.amname AS access_method,
                   ind.indisunique,
                   ind.indisprimary,
                   ind.indisvalid,
                   ind.indisready,
                   ind.indislive,
                   ind.indnkeyatts,
                   ind.indnatts,
                   ARRAY(
                       SELECT attribute.attname
                       FROM unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                       LEFT JOIN pg_attribute AS attribute
                         ON attribute.attrelid=ind.indrelid
                        AND attribute.attnum=key.attnum
                       ORDER BY key.position
                   ) AS index_columns,
                   ARRAY(
                       SELECT CASE
                           WHEN key.attnum=0 THEN NULL
                           ELSE att.attname
                       END
                       FROM unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY key.position
                   ) AS columns,
                   ARRAY(
                       SELECT option
                       FROM unnest(ind.indoption)
                            WITH ORDINALITY AS item(option, position)
                       ORDER BY item.position
                   ) AS column_options,
                   ARRAY(
                       SELECT opc.opcname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       ORDER BY item.position
                   ) AS operator_classes,
                   ARRAY(
                       SELECT opc_nsp.nspname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       JOIN pg_namespace AS opc_nsp
                         ON opc_nsp.oid=opc.opcnamespace
                       ORDER BY item.position
                   ) AS operator_class_namespaces,
                   ARRAY(
                       SELECT item.collation=att.attcollation
                       FROM unnest(ind.indcollation)
                            WITH ORDINALITY AS item(collation, position)
                       JOIN unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                         ON key.position=item.position
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY item.position
                   ) AS column_collations_match,
                   pg_get_expr(ind.indexprs, ind.indrelid) AS expressions,
                   pg_get_expr(ind.indpred, ind.indrelid) AS predicate
            FROM pg_index AS ind
            JOIN pg_class AS table_rel ON table_rel.oid=ind.indrelid
            JOIN pg_namespace AS table_nsp
              ON table_nsp.oid=table_rel.relnamespace
            JOIN pg_class AS index_rel ON index_rel.oid=ind.indexrelid
            JOIN pg_am AS access_method
              ON access_method.oid=index_rel.relam
            WHERE table_nsp.nspname=current_schema()
              AND table_rel.relname=ANY($1::text[])
              AND NOT EXISTS (
                  SELECT 1
                  FROM pg_constraint AS con
                  WHERE con.conindid=ind.indexrelid
              )
            ORDER BY table_rel.relname, index_rel.relname
            """,
            non_ticket_tables,
        )
        try:
            index_contract = {
                (str(row["table_name"]), str(row["index_name"])): (
                    tuple(str(column) for column in row["columns"]),
                    bool(row["indisunique"]),
                    row["predicate"],
                    str(row["index_relkind"]),
                    str(row["index_relpersistence"]),
                    bool(row["index_is_partition"]),
                    str(row["access_method"]),
                    bool(row["indisprimary"]),
                    bool(row["indisvalid"]),
                    bool(row["indisready"]),
                    bool(row["indislive"]),
                    int(row["indnkeyatts"]),
                    int(row["indnatts"]),
                    tuple(int(option) for option in row["column_options"]),
                    tuple(
                        str(opclass) for opclass in row["operator_classes"]
                    ),
                    tuple(
                        str(namespace)
                        for namespace in row["operator_class_namespaces"]
                    ),
                    tuple(
                        bool(value)
                        for value in row["column_collations_match"]
                    ),
                    row["expressions"],
                )
                for row in index_rows
            }
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        expected_indexes = {
            (table, name): columns
            for table, name, columns in _POSTGRES_MANAGED_INDEXES
        }
        if set(index_contract) != set(expected_indexes):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
        for key, columns in expected_indexes.items():
            actual = index_contract[key]
            if actual != (
                columns,
                False,
                None,
                "i",
                "p",
                False,
                "btree",
                False,
                True,
                True,
                True,
                len(columns),
                len(columns),
                (0,) * len(columns),
                tuple(
                    _postgres_index_opclass(key[0], column)
                    for column in columns
                ),
                ("pg_catalog",) * len(columns),
                (True,) * len(columns),
                None,
            ):
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        primary_rows = await connection.fetch(
            """
            SELECT source.relname AS table_name,
                   con.conname,
                   con.contype,
                   con.convalidated,
                   con.condeferrable,
                   con.condeferred,
                   con.conindid::bigint AS constraint_index_oid,
                   ARRAY(
                       SELECT att.attname
                       FROM unnest(con.conkey)
                            WITH ORDINALITY AS key(attnum, position)
                       JOIN pg_attribute AS att
                         ON att.attrelid=con.conrelid
                        AND att.attnum=key.attnum
                       ORDER BY key.position
                   ) AS local_columns,
                   index_rel.relkind AS index_relkind,
                   index_rel.relpersistence AS index_relpersistence,
                   index_rel.relispartition AS index_is_partition,
                   ind.indisunique,
                   ind.indisprimary,
                   ind.indisvalid,
                   ind.indisready,
                   ind.indislive
            FROM pg_constraint AS con
            JOIN pg_class AS source ON source.oid=con.conrelid
            JOIN pg_namespace AS source_nsp
              ON source_nsp.oid=source.relnamespace
            JOIN pg_class AS index_rel ON index_rel.oid=con.conindid
            JOIN pg_index AS ind ON ind.indexrelid=con.conindid
            WHERE source_nsp.nspname=current_schema()
              AND source.relname=ANY($1::text[])
              AND con.contype='p'
            ORDER BY source.relname, con.conname
            """,
            non_ticket_tables,
        )
        try:
            primary_contract = {
                (str(row["table_name"]), str(row["conname"])): (
                    str(row["contype"]),
                    bool(row["convalidated"]),
                    bool(row["condeferrable"]),
                    bool(row["condeferred"]),
                    tuple(str(value) for value in row["local_columns"]),
                    int(row["constraint_index_oid"]),
                    str(row["index_relkind"]),
                    str(row["index_relpersistence"]),
                    bool(row["index_is_partition"]),
                    bool(row["indisunique"]),
                    bool(row["indisprimary"]),
                    bool(row["indisvalid"]),
                    bool(row["indisready"]),
                    bool(row["indislive"]),
                )
                for row in primary_rows
            }
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None
        expected_primary_keys = {
            (table, name): columns
            for table, name, columns in _POSTGRES_MANAGED_PRIMARY_KEYS
        }
        if set(primary_contract) != set(expected_primary_keys):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
        for key, columns in expected_primary_keys.items():
            actual = primary_contract[key]
            if actual != (
                "p",
                True,
                False,
                False,
                columns,
                actual[5],
                "i",
                "p",
                False,
                True,
                True,
                True,
                True,
                True,
            ) or actual[5] <= 0:
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        await PostgresDatabase._validate_managed_constraints(
            connection,
            non_ticket_tables,
        )
        await PostgresDatabase._validate_managed_serials(connection)

    @staticmethod
    async def _validate_managed_constraints(
        connection: Any,
        non_ticket_tables: list[str],
    ) -> None:
        rows = await connection.fetch(
            """
            SELECT source_nsp.nspname AS source_schema,
                   source.relname AS table_name,
                   con.conname,
                   con.contype,
                   con.convalidated,
                   con.condeferrable,
                   con.condeferred,
                   con.conindid::bigint AS constraint_index_oid,
                   pg_get_constraintdef(con.oid, true) AS definition,
                   reference_nsp.nspname AS referenced_schema,
                   reference.relname AS referenced_table,
                   con.confupdtype,
                   con.confdeltype,
                   ARRAY(
                       SELECT attribute.attname
                       FROM unnest(con.conkey)
                            WITH ORDINALITY AS key(attnum, position)
                       JOIN pg_attribute AS attribute
                         ON attribute.attrelid=con.conrelid
                        AND attribute.attnum=key.attnum
                       ORDER BY key.position
                   ) AS local_columns,
                   ARRAY(
                       SELECT attribute.attname
                       FROM unnest(con.confkey)
                            WITH ORDINALITY AS key(attnum, position)
                       JOIN pg_attribute AS attribute
                         ON attribute.attrelid=con.confrelid
                        AND attribute.attnum=key.attnum
                       ORDER BY key.position
                   ) AS remote_columns,
                   index_nsp.nspname AS index_schema,
                   index_rel.relname AS index_name,
                   index_rel.relkind AS index_relkind,
                   index_rel.relpersistence AS index_relpersistence,
                   index_rel.relispartition AS index_is_partition,
                   access_method.amname AS access_method,
                   ind.indisunique,
                   ind.indisprimary,
                   ind.indisvalid,
                   ind.indisready,
                   ind.indislive,
                   ind.indnkeyatts,
                   ind.indnatts,
                   ARRAY(
                       SELECT attribute.attname
                       FROM unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                       LEFT JOIN pg_attribute AS attribute
                         ON attribute.attrelid=ind.indrelid
                        AND attribute.attnum=key.attnum
                       ORDER BY key.position
                   ) AS index_columns,
                   ARRAY(
                       SELECT option
                       FROM unnest(ind.indoption)
                            WITH ORDINALITY AS item(option, position)
                       ORDER BY item.position
                   ) AS column_options,
                   ARRAY(
                       SELECT opc.opcname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       ORDER BY item.position
                   ) AS operator_classes,
                   ARRAY(
                       SELECT opc_nsp.nspname
                       FROM unnest(ind.indclass)
                            WITH ORDINALITY AS item(opclass, position)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       JOIN pg_namespace AS opc_nsp
                         ON opc_nsp.oid=opc.opcnamespace
                       ORDER BY item.position
                   ) AS operator_class_namespaces,
                   ARRAY(
                       SELECT item.collation=attribute.attcollation
                       FROM unnest(ind.indcollation)
                            WITH ORDINALITY AS item(collation, position)
                       JOIN unnest(ind.indkey)
                            WITH ORDINALITY AS key(attnum, position)
                         ON key.position=item.position
                       LEFT JOIN pg_attribute AS attribute
                         ON attribute.attrelid=ind.indrelid
                        AND attribute.attnum=key.attnum
                       ORDER BY item.position
                   ) AS column_collations_match,
                   pg_get_expr(ind.indexprs, ind.indrelid) AS expressions,
                   pg_get_expr(ind.indpred, ind.indrelid) AS predicate
            FROM pg_constraint AS con
            JOIN pg_class AS source ON source.oid=con.conrelid
            JOIN pg_namespace AS source_nsp
              ON source_nsp.oid=source.relnamespace
            LEFT JOIN pg_class AS reference
              ON reference.oid=con.confrelid
            LEFT JOIN pg_namespace AS reference_nsp
              ON reference_nsp.oid=reference.relnamespace
            LEFT JOIN pg_class AS index_rel
              ON index_rel.oid=con.conindid
            LEFT JOIN pg_namespace AS index_nsp
              ON index_nsp.oid=index_rel.relnamespace
            LEFT JOIN pg_index AS ind
              ON ind.indexrelid=con.conindid
            LEFT JOIN pg_am AS access_method
              ON access_method.oid=index_rel.relam
            WHERE source_nsp.nspname=current_schema()
              AND source.relname=ANY($1::text[])
              AND con.contype <> 'p'
            ORDER BY source.relname, con.conname
            """,
            non_ticket_tables,
        )
        try:
            actual = {
                (str(row["table_name"]), str(row["conname"])): row
                for row in rows
            }
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR) from None

        expected_foreign = {
            (table, name): (
                local,
                parent,
                remote,
                on_delete,
                delete_code,
            )
            for (
                table,
                name,
                local,
                parent,
                remote,
                on_delete,
                delete_code,
            ) in _POSTGRES_MANAGED_FOREIGN_KEYS
        }
        expected_unique = {
            (table, name): columns
            for table, name, columns in _POSTGRES_MANAGED_UNIQUES
        }
        expected_checks = {
            (
                table,
                _postgres_finite_check_name(table, column),
            ): (
                f"CHECK ({column} IS NULL OR isfinite({column}))"
                if nullable
                else f"CHECK (isfinite({column}))"
            )
            for table, column, nullable in (
                _POSTGRES_MANAGED_FINITE_CHECKS
            )
        }
        expected_checks[
            (
                "rate_limit_events",
                "ck_rate_limit_events_blocked_bool",
            )
        ] = "CHECK (blocked = ANY (ARRAY[0, 1]))"
        expected_keys = (
            set(expected_foreign)
            | set(expected_unique)
            | set(expected_checks)
        )
        if len(rows) != len(actual) or set(actual) != expected_keys:
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

        for key, contract in actual.items():
            try:
                source_schema = str(contract["source_schema"])
                common = (
                    bool(contract["convalidated"]),
                    bool(contract["condeferrable"]),
                    bool(contract["condeferred"]),
                )
                definition = _postgres_constraint_definition(
                    contract["definition"]
                )
                local_columns = tuple(
                    str(column) for column in contract["local_columns"]
                )
                remote_columns = tuple(
                    str(column) for column in contract["remote_columns"]
                )
            except (KeyError, TypeError, ValueError):
                raise RuntimeError(
                    _POSTGRES_MANAGED_SCHEMA_ERROR
                ) from None
            if not source_schema or common != (True, False, False):
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

            if key in expected_checks:
                if (
                    str(contract["contype"]) != "c"
                    or definition != expected_checks[key]
                    or local_columns == ()
                    or remote_columns
                    or int(contract["constraint_index_oid"]) != 0
                ):
                    raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
                continue

            if key in expected_foreign:
                (
                    expected_local,
                    parent,
                    expected_remote,
                    on_delete,
                    delete_code,
                ) = expected_foreign[key]
                expected_definition = (
                    f"FOREIGN KEY ({', '.join(expected_local)}) "
                    f"REFERENCES {parent}({', '.join(expected_remote)}) "
                    f"ON DELETE {on_delete}"
                )
                if (
                    str(contract["contype"]) != "f"
                    or definition != expected_definition
                    or local_columns != expected_local
                    or remote_columns != expected_remote
                    or str(contract["referenced_schema"])
                    != source_schema
                    or str(contract["referenced_table"]) != parent
                    or str(contract["confupdtype"]) != "a"
                    or str(contract["confdeltype"]) != delete_code
                ):
                    raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
                try:
                    foreign_index_contract = (
                        int(contract["constraint_index_oid"]),
                        str(contract["index_schema"]),
                        str(contract["index_name"]),
                        str(contract["index_relkind"]),
                        str(contract["index_relpersistence"]),
                        bool(contract["index_is_partition"]),
                        str(contract["access_method"]),
                        bool(contract["indisunique"]),
                        bool(contract["indisprimary"]),
                        bool(contract["indisvalid"]),
                        bool(contract["indisready"]),
                        bool(contract["indislive"]),
                        int(contract["indnkeyatts"]),
                        int(contract["indnatts"]),
                        tuple(
                            str(column)
                            for column in contract["index_columns"]
                        ),
                        tuple(
                            int(option)
                            for option in contract["column_options"]
                        ),
                        tuple(
                            str(opclass)
                            for opclass in contract["operator_classes"]
                        ),
                        tuple(
                            str(namespace)
                            for namespace in contract[
                                "operator_class_namespaces"
                            ]
                        ),
                        tuple(
                            bool(value)
                            for value in contract[
                                "column_collations_match"
                            ]
                        ),
                        contract["expressions"],
                        contract["predicate"],
                    )
                except (KeyError, TypeError, ValueError):
                    raise RuntimeError(
                        _POSTGRES_MANAGED_SCHEMA_ERROR
                    ) from None
                if foreign_index_contract != (
                    foreign_index_contract[0],
                    source_schema,
                    f"{parent}_pkey",
                    "i",
                    "p",
                    False,
                    "btree",
                    True,
                    True,
                    True,
                    True,
                    True,
                    len(expected_remote),
                    len(expected_remote),
                    expected_remote,
                    (0,) * len(expected_remote),
                    ("text_ops",) * len(expected_remote),
                    ("pg_catalog",) * len(expected_remote),
                    (True,) * len(expected_remote),
                    None,
                    None,
                ) or foreign_index_contract[0] <= 0:
                    raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
                continue

            columns = expected_unique[key]
            expected_definition = f"UNIQUE ({', '.join(columns)})"
            try:
                unique_contract = (
                    str(contract["contype"]),
                    definition,
                    local_columns,
                    contract["referenced_schema"],
                    contract["referenced_table"],
                    remote_columns,
                    str(contract["index_schema"]),
                    str(contract["index_name"]),
                    str(contract["index_relkind"]),
                    str(contract["index_relpersistence"]),
                    bool(contract["index_is_partition"]),
                    str(contract["access_method"]),
                    bool(contract["indisunique"]),
                    bool(contract["indisprimary"]),
                    bool(contract["indisvalid"]),
                    bool(contract["indisready"]),
                    bool(contract["indislive"]),
                    int(contract["indnkeyatts"]),
                    int(contract["indnatts"]),
                    tuple(
                        str(column)
                        for column in contract["index_columns"]
                    ),
                    tuple(
                        int(option)
                        for option in contract["column_options"]
                    ),
                    tuple(
                        str(opclass)
                        for opclass in contract["operator_classes"]
                    ),
                    tuple(
                        str(namespace)
                        for namespace in (
                            contract["operator_class_namespaces"]
                        )
                    ),
                    tuple(
                        bool(value)
                        for value in contract[
                            "column_collations_match"
                        ]
                    ),
                    contract["expressions"],
                    contract["predicate"],
                )
            except (KeyError, TypeError, ValueError):
                raise RuntimeError(
                    _POSTGRES_MANAGED_SCHEMA_ERROR
                ) from None
            if unique_contract != (
                "u",
                expected_definition,
                columns,
                None,
                None,
                (),
                source_schema,
                key[1],
                "i",
                "p",
                False,
                "btree",
                True,
                False,
                True,
                True,
                True,
                len(columns),
                len(columns),
                columns,
                (0,) * len(columns),
                ("text_ops",) * len(columns),
                ("pg_catalog",) * len(columns),
                (True,) * len(columns),
                None,
                None,
            ) or int(contract["constraint_index_oid"]) <= 0:
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)

    @staticmethod
    async def _validate_managed_serials(connection: Any) -> None:
        rows = await connection.fetch(
            """
            SELECT sequence_nsp.nspname AS sequence_schema,
                   sequence_rel.relname AS sequence_name,
                   sequence_rel.relkind,
                   sequence_rel.relpersistence,
                   format_type(sequence_def.seqtypid, NULL) AS data_type,
                   sequence_def.seqstart,
                   sequence_def.seqincrement,
                   sequence_def.seqmax,
                   sequence_def.seqmin,
                   sequence_def.seqcache,
                   sequence_def.seqcycle,
                   owner_nsp.nspname AS owner_schema,
                   owner_rel.relname AS owner_table,
                   owner_att.attname AS owner_column,
                   dependency.deptype,
                   format_type(
                       owner_att.atttypid,
                       owner_att.atttypmod
                   ) AS owner_data_type,
                   owner_att.attnotnull,
                   owner_att.attidentity,
                   owner_att.attgenerated,
                   owner_att.attcollation=owner_type.typcollation
                       AS collation_is_default,
                   pg_get_expr(
                       owner_default.adbin,
                       owner_default.adrelid
                   ) AS column_default
            FROM pg_class AS sequence_rel
            JOIN pg_namespace AS sequence_nsp
              ON sequence_nsp.oid=sequence_rel.relnamespace
            JOIN pg_sequence AS sequence_def
              ON sequence_def.seqrelid=sequence_rel.oid
            LEFT JOIN pg_depend AS dependency
              ON dependency.classid='pg_class'::regclass
             AND dependency.objid=sequence_rel.oid
             AND dependency.objsubid=0
             AND dependency.refclassid='pg_class'::regclass
             AND dependency.deptype IN ('a', 'i')
            LEFT JOIN pg_class AS owner_rel
              ON owner_rel.oid=dependency.refobjid
            LEFT JOIN pg_namespace AS owner_nsp
              ON owner_nsp.oid=owner_rel.relnamespace
            LEFT JOIN pg_attribute AS owner_att
              ON owner_att.attrelid=dependency.refobjid
             AND owner_att.attnum=dependency.refobjsubid
            LEFT JOIN pg_type AS owner_type
              ON owner_type.oid=owner_att.atttypid
            LEFT JOIN pg_attrdef AS owner_default
              ON owner_default.adrelid=owner_att.attrelid
             AND owner_default.adnum=owner_att.attnum
            WHERE sequence_nsp.nspname=current_schema()
              AND sequence_rel.relname=ANY($1::text[])
            ORDER BY sequence_rel.relname
            """,
            ["audit_log_id_seq", "rate_limit_events_id_seq"],
        )
        expected = {
            "audit_log_id_seq": (
                "audit_log",
                "id",
                "nextval('audit_log_id_seq'::regclass)",
            ),
            "rate_limit_events_id_seq": (
                "rate_limit_events",
                "id",
                "nextval('rate_limit_events_id_seq'::regclass)",
            ),
        }
        if len(rows) != len(expected):
            raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
        seen: set[str] = set()
        for row in rows:
            try:
                name = str(row["sequence_name"])
                owner = expected.get(name)
                contract = (
                    str(row["relkind"]),
                    str(row["relpersistence"]),
                    str(row["data_type"]),
                    int(row["seqstart"]),
                    int(row["seqincrement"]),
                    int(row["seqmax"]),
                    int(row["seqmin"]),
                    int(row["seqcache"]),
                    bool(row["seqcycle"]),
                    str(row["owner_schema"]),
                    str(row["owner_table"]),
                    str(row["owner_column"]),
                    str(row["deptype"]),
                    str(row["owner_data_type"]),
                    bool(row["attnotnull"]),
                    str(row["attidentity"]),
                    str(row["attgenerated"]),
                    bool(row["collation_is_default"]),
                    row["column_default"],
                )
            except (KeyError, TypeError, ValueError):
                raise RuntimeError(
                    _POSTGRES_MANAGED_SCHEMA_ERROR
                ) from None
            if owner is None or name in seen:
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
            if contract != (
                "S",
                "p",
                "integer",
                1,
                1,
                2147483647,
                1,
                1,
                False,
                str(row["sequence_schema"]),
                owner[0],
                owner[1],
                "a",
                "integer",
                True,
                "",
                "",
                True,
                owner[2],
            ):
                raise RuntimeError(_POSTGRES_MANAGED_SCHEMA_ERROR)
            seen.add(name)

    async def _init_schema(self) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                try:
                    revision = await self._managed_schema_revision(conn)
                except (
                    _PostgresManagedSchemaError,
                    _PostgresMigrationRequiredError,
                ):
                    raise
                except RuntimeError as exc:
                    if str(exc) == _POSTGRES_MANAGED_SCHEMA_ERROR:
                        raise _PostgresManagedSchemaError(
                            _POSTGRES_MANAGED_SCHEMA_ERROR
                        ) from None
                    raise RuntimeError(
                        _POSTGRES_SCHEMA_VALIDATION_ERROR
                    ) from None
                except Exception:
                    raise RuntimeError(
                        _POSTGRES_SCHEMA_VALIDATION_ERROR
                    ) from None
                if revision is not None:
                    try:
                        await self._validate_managed_schema(conn)
                        await self._validate_websocket_ticket_schema(conn)
                    except _PostgresManagedSchemaError:
                        raise
                    except RuntimeError as exc:
                        if str(exc) == _POSTGRES_MANAGED_SCHEMA_ERROR:
                            raise _PostgresManagedSchemaError(
                                _POSTGRES_MANAGED_SCHEMA_ERROR
                            ) from None
                        if str(exc) == (
                            "Incompatible WebSocket ticket schema"
                        ):
                            raise
                        raise RuntimeError(
                            _POSTGRES_SCHEMA_VALIDATION_ERROR
                        ) from None
                    except Exception:
                        raise RuntimeError(
                            _POSTGRES_SCHEMA_VALIDATION_ERROR
                        ) from None
                else:
                    ticket_table_exists = bool(
                        await conn.fetchval(
                            """
                            SELECT EXISTS(
                                SELECT 1
                                FROM pg_class AS rel
                                JOIN pg_namespace AS nsp
                                  ON nsp.oid=rel.relnamespace
                                WHERE nsp.nspname=current_schema()
                                  AND rel.relname='websocket_tickets'
                            )
                            """
                        )
                    )
                    if ticket_table_exists:
                        await self._validate_websocket_ticket_schema(conn)
                    await conn.execute(_PG_CREATE_TABLES)
                    await self._validate_websocket_ticket_schema(conn)
        logger.info("pg_schema_ready")

    @staticmethod
    async def _validate_websocket_ticket_schema(connection: Any) -> None:
        """Reject any ticket catalog that differs from the owned schema."""
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
                       SELECT COUNT(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhrelid=rel.oid
                   ) AS parent_count,
                   (
                       SELECT COUNT(*)
                       FROM pg_inherits AS inherited
                       WHERE inherited.inhparent=rel.oid
                   ) AS child_count,
                   (
                       SELECT COUNT(*)
                       FROM pg_policy AS policy
                       WHERE policy.polrelid=rel.oid
                   ) AS policy_count,
                   (
                       SELECT COUNT(*)
                       FROM pg_trigger AS trg
                       WHERE trg.tgrelid=rel.oid
                         AND NOT trg.tgisinternal
                   ) AS user_trigger_count,
                   (
                       SELECT COUNT(*)
                       FROM pg_rewrite AS rewrite
                       WHERE rewrite.ev_class=rel.oid
                   ) AS user_rule_count
            FROM pg_class AS rel
            JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
            WHERE nsp.nspname=current_schema()
              AND rel.relname='websocket_tickets'
            """
        )
        if relation is None:
            raise RuntimeError("Incompatible WebSocket ticket schema")
        table_oid = int(relation["table_oid"])
        schema_oid = int(relation["schema_oid"])
        schema_name = str(relation["schema_name"])
        relation_contract = (
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
        )
        if relation_contract != (
            "r",
            "p",
            False,
            False,
            False,
            0,
            0,
            0,
            0,
            0,
        ):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        rows = await connection.fetch(
            """
            SELECT att.attname AS column_name,
                   pg_catalog.format_type(att.atttypid, att.atttypmod) AS data_type,
                   att.attnotnull,
                   att.attidentity,
                   att.attgenerated,
                   att.attcollation=typ.typcollation AS collation_is_default,
                   pg_get_expr(def.adbin, def.adrelid) AS column_default
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
        actual_columns = [
            (
                str(row["column_name"]),
                str(row["data_type"]),
                bool(row["attnotnull"]),
                str(row["attidentity"]),
                str(row["attgenerated"]),
                bool(row["collation_is_default"]),
                None if row["column_default"] is None else str(row["column_default"]),
            )
            for row in rows
        ]
        expected_columns = [
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
        ]
        if actual_columns != expected_columns:
            raise RuntimeError("Incompatible WebSocket ticket schema")

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
                   ref_nsp.nspname AS referenced_schema,
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
        actual_constraints = {
            str(row["conname"]): row
            for row in constraint_rows
        }
        expected_constraint_names = {
            "ck_ws_ticket_bearer_expires_finite",
            "ck_ws_ticket_consumed_at",
            "ck_ws_ticket_consumed_finite",
            "ck_ws_ticket_created_at",
            "ck_ws_ticket_created_finite",
            "ck_ws_ticket_expires_at",
            "ck_ws_ticket_expires_finite",
            "ck_ws_ticket_hash",
            "ck_ws_ticket_kind",
            "ck_ws_ticket_source_shape",
            "ck_ws_ticket_time_order",
            "fk_ws_ticket_api_key",
            "fk_ws_ticket_campaign",
            "fk_ws_ticket_user",
            "websocket_tickets_pkey",
        }
        if set(actual_constraints) != expected_constraint_names:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        index_rows = await connection.fetch(
            """
            SELECT ind.indrelid::bigint AS table_oid,
                   ind.indexrelid::bigint AS index_oid,
                   idx.relnamespace::bigint AS index_schema_oid,
                   idx_nsp.nspname AS index_schema,
                   idx.relname AS index_name,
                   idx.relkind AS index_relkind,
                   idx.relpersistence AS index_relpersistence,
                   idx.relispartition AS index_is_partition,
                   am.amname AS access_method,
                   ind.indisunique,
                   ind.indisprimary,
                   ind.indisvalid,
                   ind.indisready,
                   ind.indislive,
                   ind.indnkeyatts,
                   ind.indnatts,
                   ARRAY(
                       SELECT CASE
                           WHEN key.attnum=0 THEN NULL
                           ELSE att.attname
                       END
                       FROM unnest(ind.indkey) WITH ORDINALITY AS key(attnum, ordinality)
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY key.ordinality
                   ) AS columns,
                   ARRAY(
                       SELECT option
                       FROM unnest(ind.indoption) WITH ORDINALITY AS item(option, ordinality)
                       ORDER BY item.ordinality
                   ) AS column_options,
                   ARRAY(
                       SELECT opc.opcname
                       FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       ORDER BY item.ordinality
                   ) AS operator_classes,
                   ARRAY(
                       SELECT opc.oid::bigint
                       FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       ORDER BY item.ordinality
                   ) AS operator_class_oids,
                   ARRAY(
                       SELECT opc_nsp.nspname
                       FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                       JOIN pg_opclass AS opc ON opc.oid=item.opclass
                       JOIN pg_namespace AS opc_nsp
                         ON opc_nsp.oid=opc.opcnamespace
                       ORDER BY item.ordinality
                   ) AS operator_class_namespaces,
                   ARRAY(
                       SELECT item.collation=att.attcollation
                       FROM unnest(ind.indcollation) WITH ORDINALITY
                            AS item(collation, ordinality)
                       JOIN unnest(ind.indkey) WITH ORDINALITY
                            AS key(attnum, ordinality)
                         ON key.ordinality=item.ordinality
                       LEFT JOIN pg_attribute AS att
                         ON att.attrelid=ind.indrelid
                        AND att.attnum=key.attnum
                       ORDER BY item.ordinality
                   ) AS column_collations_match,
                   pg_get_expr(ind.indexprs, ind.indrelid) AS expressions,
                   pg_get_expr(ind.indpred, ind.indrelid) AS predicate,
                   pg_get_indexdef(ind.indexrelid) AS definition
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
        if set(canonical_opclasses) != {"text_ops", "timestamptz_ops"}:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        index_oids: set[int] = set()
        for row in index_rows:
            operator_classes = tuple(
                str(opclass) for opclass in row["operator_classes"]
            )
            operator_class_oids = tuple(
                int(opclass_oid) for opclass_oid in row["operator_class_oids"]
            )
            canonical_oids = tuple(
                canonical_opclasses.get(opclass, -1)
                for opclass in operator_classes
            )
            index_oid = int(row["index_oid"])
            identity_is_exact = (
                int(row["table_oid"]) == table_oid
                and int(row["index_schema_oid"]) == schema_oid
                and str(row["index_schema"]) == schema_name
                and str(row["index_relkind"]) == "i"
                and str(row["index_relpersistence"]) == "p"
                and not bool(row["index_is_partition"])
                and tuple(
                    str(namespace)
                    for namespace in row["operator_class_namespaces"]
                )
                == ("pg_catalog",) * len(operator_classes)
                and operator_class_oids == canonical_oids
                and index_oid > 0
                and index_oid not in index_oids
            )
            if not identity_is_exact:
                raise RuntimeError("Incompatible WebSocket ticket schema")
            index_oids.add(index_oid)

        actual_indexes = {
            str(row["index_name"]): (
                str(row["access_method"]),
                bool(row["indisunique"]),
                bool(row["indisprimary"]),
                bool(row["indisvalid"]),
                bool(row["indisready"]),
                bool(row["indislive"]),
                int(row["indnkeyatts"]),
                int(row["indnatts"]),
                tuple(
                    None if column is None else str(column)
                    for column in row["columns"]
                ),
                tuple(int(option) for option in row["column_options"]),
                tuple(str(opclass) for opclass in row["operator_classes"]),
                tuple(bool(value) for value in row["column_collations_match"]),
                None if row["expressions"] is None else str(row["expressions"]),
                None if row["predicate"] is None else str(row["predicate"]),
            )
            for row in index_rows
        }
        expected_indexes = {
            "idx_ws_tickets_api_key": (
                "btree", False, False, True, True, True,
                1, 1, ("api_key_id",), (0,), ("text_ops",), (True,), None, None,
            ),
            "idx_ws_tickets_campaign": (
                "btree", False, False, True, True, True,
                1, 1, ("campaign_id",), (0,), ("text_ops",), (True,), None, None,
            ),
            "idx_ws_tickets_expires": (
                "btree", False, False, True, True, True,
                1, 1, ("expires_at",), (0,), ("timestamptz_ops",), (True,),
                None, None,
            ),
            "idx_ws_tickets_user": (
                "btree", False, False, True, True, True,
                1, 1, ("user_id",), (0,), ("text_ops",), (True,), None, None,
            ),
            "websocket_tickets_pkey": (
                "btree", True, True, True, True, True,
                1, 1, ("ticket_hash",), (0,), ("text_ops",), (True,), None, None,
            ),
        }
        if actual_indexes != expected_indexes:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        expected_constraint_fragments = {
            "websocket_tickets_pkey": ("p", "PRIMARY KEY (ticket_hash)"),
            "fk_ws_ticket_campaign": (
                "f",
                "FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE",
            ),
            "fk_ws_ticket_user": (
                "f",
                "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
            ),
            "fk_ws_ticket_api_key": (
                "f",
                "FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE",
            ),
        }
        for name, definition in expected_constraint_fragments.items():
            row = actual_constraints[name]
            if (
                str(row["contype"]) != definition[0]
                or not bool(row["convalidated"])
                or bool(row["condeferrable"])
                or bool(row["condeferred"])
                or " ".join(str(row["definition"]).split()) != definition[1]
            ):
                raise RuntimeError("Incompatible WebSocket ticket schema")

        referenced_schema = str(await connection.fetchval("SELECT current_schema()"))
        expected_foreign_keys = {
            "fk_ws_ticket_campaign": (
                ("campaign_id",), referenced_schema, "campaigns", ("id",), "a", "c",
            ),
            "fk_ws_ticket_user": (
                ("user_id",), referenced_schema, "users", ("id",), "a", "c",
            ),
            "fk_ws_ticket_api_key": (
                ("api_key_id",), referenced_schema, "api_keys", ("id",), "a", "c",
            ),
        }
        referenced_rows = await connection.fetch(
            """
            SELECT rel.relname, rel.oid::bigint AS relation_oid
            FROM pg_class AS rel
            WHERE rel.relnamespace=$1::oid
              AND rel.relname=ANY($2::text[])
            """,
            schema_oid,
            ["api_keys", "campaigns", "users"],
        )
        referenced_oids = {
            str(row["relname"]): int(row["relation_oid"])
            for row in referenced_rows
        }
        if set(referenced_oids) != {"api_keys", "campaigns", "users"}:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        if any(
            int(row["table_oid"]) != table_oid
            for row in actual_constraints.values()
        ):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        for name, expected in expected_foreign_keys.items():
            row = actual_constraints[name]
            actual = (
                tuple(str(column) for column in row["local_columns"]),
                str(row["referenced_schema"]),
                str(row["referenced_table"]),
                tuple(str(column) for column in row["remote_columns"]),
                str(row["confupdtype"]),
                str(row["confdeltype"]),
            )
            reference_identity_is_exact = (
                row["referenced_schema_oid"] is not None
                and int(row["referenced_schema_oid"]) == schema_oid
                and int(row["referenced_oid"])
                == referenced_oids[expected[2]]
            )
            if actual != expected or not reference_identity_is_exact:
                raise RuntimeError("Incompatible WebSocket ticket schema")

        primary = actual_constraints["websocket_tickets_pkey"]
        if (
            tuple(str(column) for column in primary["local_columns"])
            != ("ticket_hash",)
            or tuple(primary["remote_columns"])
            or primary["referenced_schema"] is not None
            or primary["referenced_table"] is not None
            or int(primary["constraint_index_oid"])
            != next(
                int(row["index_oid"])
                for row in index_rows
                if str(row["index_name"]) == "websocket_tickets_pkey"
            )
        ):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        expected_check_definitions = {
            "ck_ws_ticket_hash": (
                "CHECK (ticket_hash ~ '^[0-9a-f]{64}$'::text)"
            ),
            "ck_ws_ticket_kind": (
                "CHECK (credential_kind = ANY "
                "(ARRAY['bearer'::text, 'api_key'::text]))"
            ),
            "ck_ws_ticket_created_at": "CHECK (created_at < expires_at)",
            "ck_ws_ticket_expires_at": "CHECK (expires_at > created_at)",
            "ck_ws_ticket_consumed_at": (
                "CHECK (consumed_at IS NULL OR consumed_at < expires_at)"
            ),
            "ck_ws_ticket_bearer_expires_finite": (
                "CHECK (bearer_expires_at IS NULL "
                "OR isfinite(bearer_expires_at))"
            ),
            "ck_ws_ticket_created_finite": "CHECK (isfinite(created_at))",
            "ck_ws_ticket_expires_finite": "CHECK (isfinite(expires_at))",
            "ck_ws_ticket_consumed_finite": (
                "CHECK (consumed_at IS NULL OR isfinite(consumed_at))"
            ),
            "ck_ws_ticket_time_order": (
                "CHECK (expires_at > created_at AND "
                "(consumed_at IS NULL OR consumed_at < expires_at))"
            ),
            "ck_ws_ticket_source_shape": (
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
                "AND required_scope = 'read'::text)"
            ),
        }
        for name, expected_definition in expected_check_definitions.items():
            row = actual_constraints[name]
            if (
                str(row["contype"]) != "c"
                or not bool(row["convalidated"])
                or bool(row["condeferrable"])
                or bool(row["condeferred"])
                or " ".join(str(row["definition"]).split())
                != expected_definition
            ):
                raise RuntimeError("Incompatible WebSocket ticket schema")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _enc_val(self, v: str | None) -> str | None:
        return self._enc.encrypt(v) if self._enc and v else v

    def _dec_val(self, v: str | None) -> str | None:
        return self._enc.decrypt(v) if self._enc and v else v

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        """Convert asyncpg Record to plain dict; convert datetime → ISO string."""
        if row is None:
            return {}
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d

    # ── Campaigns ──────────────────────────────────────────────────────────────

    async def save_campaign(self, c: Any) -> None:
        from ares.core.campaign import Campaign
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO campaigns(id,name,client,operator,noise_profile,status,scope_json,targets_json,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO UPDATE SET
                  name=EXCLUDED.name, client=EXCLUDED.client, operator=EXCLUDED.operator,
                  noise_profile=EXCLUDED.noise_profile, status=EXCLUDED.status,
                  scope_json=EXCLUDED.scope_json, targets_json=EXCLUDED.targets_json,
                  notes=EXCLUDED.notes,
                  updated_at=now()
            """, c.id, c.name, c.client, c.operator,
                c.noise_profile.value if hasattr(c.noise_profile, "value") else str(c.noise_profile),
                c.status.value if hasattr(c.status, "value") else str(c.status),
                json.dumps([s.model_dump() for s in c.scope]),
                json.dumps(c.targets), c.notes)

    async def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_id)
        return self._row_to_dict(row) if row else None

    async def list_campaigns(
        self, page: int = 1, per_page: int = 50, operator: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        offset = (page - 1) * per_page
        where  = "WHERE operator=$1" if operator else ""
        params = [operator] if operator else []

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM campaigns {where}", *params
            )
            rows = await conn.fetch(
                f"SELECT * FROM campaigns {where} ORDER BY created_at DESC LIMIT ${ len(params)+1 } OFFSET ${ len(params)+2 }",
                *params, per_page, offset,
            )
        return [self._row_to_dict(r) for r in rows], total or 0

    async def delete_campaign(self, campaign_id: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for statement in (
                    "DELETE FROM loot WHERE campaign_id=$1",
                    "DELETE FROM credentials WHERE campaign_id=$1",
                    "DELETE FROM hosts WHERE campaign_id=$1",
                    "DELETE FROM findings WHERE campaign_id=$1",
                ):
                    await conn.execute(statement, campaign_id)
                result = await conn.execute(
                    "DELETE FROM campaigns WHERE id=$1", campaign_id
                )
        return result == "DELETE 1"

    # ── Findings ───────────────────────────────────────────────────────────────

    async def save_finding(self, campaign_id: str, f: Any, module_id: str = "") -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO findings
                (id,campaign_id,module_id,title,description,severity,cvss_score,cvss_vector,
                 confidence,mitre_technique,mitre_tactic,evidence_json,remediation,host,trace_id,
                 validated,false_positive)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                ON CONFLICT(id) DO UPDATE SET
                  title=EXCLUDED.title, description=EXCLUDED.description,
                  severity=EXCLUDED.severity, evidence_json=EXCLUDED.evidence_json,
                  validated=EXCLUDED.validated, false_positive=EXCLUDED.false_positive
            """, f.id, campaign_id, module_id or getattr(f, "module_id", ""),
                f.title, f.description,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                getattr(f, "cvss_score", 0.0), getattr(f, "cvss_vector", ""),
                f.confidence, f.mitre_technique, f.mitre_tactic,
                json.dumps(f.evidence), f.remediation, f.host,
                getattr(f, "trace_id", ""),
                int(bool(getattr(f, "validated", False))),
                int(bool(getattr(f, "false_positive", False))))

    async def list_findings(
        self,
        campaign_id:    str,
        page:           int = 1,
        per_page:       int = 50,
        severity:       str | None = None,
        false_positive: bool | None = None,
        validated:      bool | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conditions = ["campaign_id=$1"]
        params: list[Any] = [campaign_id]

        if severity:
            params.append(severity);        conditions.append(f"severity=${len(params)}")
        if false_positive is not None:
            params.append(int(false_positive)); conditions.append(f"false_positive=${len(params)}")
        if validated is not None:
            params.append(int(validated));  conditions.append(f"validated=${len(params)}")

        where  = " AND ".join(conditions)
        offset = (page - 1) * per_page

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(f"SELECT COUNT(*) FROM findings WHERE {where}", *params)
            params_page = params + [per_page, offset]
            rows = await conn.fetch(
                f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC"
                f" LIMIT ${len(params)+1} OFFSET ${len(params)+2}",
                *params_page,
            )
        return [self._row_to_dict(r) for r in rows], total or 0

    async def get_findings(self, campaign_id: str, confirmed_only: bool = False) -> list[dict]:
        where = (
            "campaign_id=$1 AND validated=1 AND false_positive=0"
            if confirmed_only
            else "campaign_id=$1"
        )
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC",
                campaign_id,
            )
        return [self._row_to_dict(r) for r in rows]

    async def get_finding_stats(self, campaign_id: str) -> dict[str, Any]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT severity, COUNT(*) as n FROM findings WHERE campaign_id=$1 GROUP BY severity",
                campaign_id,
            )
        stats: dict[str, Any] = {"total": 0, "critical":0,"high":0,"medium":0,"low":0,"info":0}
        for r in rows:
            stats[r["severity"]] = r["n"]
            stats["total"] += r["n"]
        return stats

    async def get_monthly_confirmed_finding_stats(self) -> dict[str, Any]:
        """Return confirmed findings grouped by day in the current UTC month."""
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if period_start.month == 12:
            next_month = period_start.replace(year=period_start.year + 1, month=1)
        else:
            next_month = period_start.replace(month=period_start.month + 1)
        period = period_start.strftime("%Y-%m")
        async with self._pool.acquire() as conn:
            confirmed_findings = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE validated=1
                  AND false_positive=0
                """
            )
            rows = await conn.fetch(
                """
                SELECT (discovered_at AT TIME ZONE 'UTC')::date AS finding_date,
                       COUNT(*) AS n
                FROM findings
                WHERE validated=1
                  AND false_positive=0
                  AND discovered_at >= $1
                  AND discovered_at < $2
                GROUP BY 1
                ORDER BY 1
                """,
                period_start,
                next_month,
            )
        series = [
            {"date": row["finding_date"].isoformat(), "count": int(row["n"])}
            for row in rows
        ]
        return {
            "period": period,
            "label": "Security signals this cycle",
            "total": sum(item["count"] for item in series),
            "confirmed_findings": int(confirmed_findings or 0),
            "series": series,
        }

    # ── Hosts ──────────────────────────────────────────────────────────────────

    async def record_module_run(
        self,
        campaign_id: str,
        module_id: str,
        outcome: str,
        success: bool,
        duration_ms: float,
    ) -> None:
        """Persist non-sensitive execution metadata for restart-safe telemetry."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO module_runs
                    (id, campaign_id, module_id, outcome, success, duration_ms, completed_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                str(uuid.uuid4()),
                campaign_id,
                module_id,
                outcome,
                int(bool(success)),
                max(0.0, float(duration_ms or 0.0)),
                datetime.now(timezone.utc),
            )

    async def get_telemetry_stats(self) -> dict[str, Any]:
        """Aggregate persisted execution, finding, and discovered-host telemetry."""
        async with self._pool.acquire() as conn:
            run_rows = await conn.fetch(
                "SELECT success, duration_ms, completed_at FROM module_runs ORDER BY completed_at"
            )
            confirmed_findings = int(
                await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM findings
                    WHERE validated=1 AND false_positive=0
                    """
                )
                or 0
            )
            discovered_hosts = int(await conn.fetchval("SELECT COUNT(*) FROM hosts") or 0)

        total = len(run_rows)
        success = sum(int(row["success"]) for row in run_rows)
        failed = total - success
        durations = sorted(float(row["duration_ms"] or 0.0) for row in run_rows)

        def percentile(fraction: float) -> float | None:
            if not durations:
                return None
            index = max(0, min(len(durations) - 1, int(len(durations) * fraction + 0.999999) - 1))
            return round(durations[index], 1)

        recent_cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        recent_runs = sum(
            1
            for row in run_rows
            if row["completed_at"] is not None and row["completed_at"] >= recent_cutoff
        )
        return {
            "modules": {
                "total": total,
                "success": success,
                "failed": failed,
                "error_rate": failed / total if total else 0.0,
            },
            "findings": confirmed_findings,
            "latency_ms": {
                "p50": percentile(0.50),
                "p95": percentile(0.95),
                "p99": percentile(0.99),
            },
            "throughput": {
                "tasks_per_min": float(recent_runs) if recent_runs else None,
            },
            "hosts": {
                "available": False,
                "discovered": discovered_hosts,
                "owned": None,
            },
        }

    async def upsert_host(self, h: Any) -> str:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO hosts(id,campaign_id,ip_address,hostname,fqdn,os,os_version,
                    domain,is_dc,open_ports_json,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT(campaign_id,ip_address) DO UPDATE SET
                  hostname=EXCLUDED.hostname, os=EXCLUDED.os, is_dc=EXCLUDED.is_dc,
                  open_ports_json=EXCLUDED.open_ports_json, last_seen=now()
            """, h.id, h.campaign_id, h.ip_address, h.hostname, h.fqdn,
                h.os, h.os_version, h.domain, int(h.is_dc),
                json.dumps(h.open_ports), json.dumps(h.tags))
        return h.id

    async def get_hosts(self, campaign_id: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM hosts WHERE campaign_id=$1 ORDER BY first_seen", campaign_id
            )
        return [self._row_to_dict(r) for r in rows]

    # ── Credentials ────────────────────────────────────────────────────────────

    async def save_credential(self, c: Any) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO credentials
                (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO NOTHING
            """, c.id, c.campaign_id, c.host_id, c.username,
                self._enc_val(c.secret), c.cred_type, c.domain, c.source_module, c.notes)

    async def get_credentials(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM credentials WHERE campaign_id=$1 ORDER BY captured_at", campaign_id
            )
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            d["secret"] = self._dec_val(d.get("secret_enc")) if decrypt else None
            result.append(d)
        return result

    async def save_credential_preencrypted(self, cred: Any) -> None:
        """
        Persist a credential whose secret is ALREADY Fernet-encrypted by
        CredentialVault. Skips _enc_val() to prevent double-encryption.
        Mirrors database.py implementation — required by engine._persist_vault_credentials().
        """
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO credentials
                    (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO UPDATE SET
                    secret_enc    = EXCLUDED.secret_enc,
                    source_module = EXCLUDED.source_module,
                    notes         = EXCLUDED.notes
            """, cred.id, cred.campaign_id, cred.host_id, cred.username,
                cred.secret,   # already vault-encrypted — store verbatim, no _enc_val()
                cred.cred_type, cred.domain, cred.source_module, cred.notes)

    async def load_credentials_raw(self, campaign_id: str) -> list[dict]:
        """
        Load all credentials for a campaign as raw dicts.
        Secrets returned as-is (Fernet-encrypted by CredentialVault) —
        use CredentialVault.restore_from_db_records() to re-hydrate.
        Required by server.py POST /campaigns/{id}/restore-vault endpoint.
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM credentials WHERE campaign_id=$1 ORDER BY captured_at DESC",
                campaign_id,
            )
        return [self._row_to_dict(r) for r in rows]

    # ── Loot ───────────────────────────────────────────────────────────────────

    async def save_loot(self, l: Any) -> None:
        content_str = json.dumps(l.content) if isinstance(l.content, (dict, list)) else l.content
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO loot
                (id,campaign_id,host_id,loot_type,name,description,content_enc,
                 path_on_target,source_module,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                ON CONFLICT(id) DO NOTHING
            """, l.id, l.campaign_id, l.host_id, l.loot_type, l.name, l.description,
                self._enc_val(content_str), l.path_on_target, l.source_module,
                json.dumps(l.tags))

    async def get_loot(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM loot WHERE campaign_id=$1 ORDER BY captured_at", campaign_id
            )
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            d["content"] = self._dec_val(d.get("content_enc")) if decrypt else None
            result.append(d)
        return result

    async def save_campaign_graph(self, campaign_id: str, graph: dict[str, Any]) -> None:
        """Persist a sanitized graph snapshot in the existing encrypted loot store."""
        graph_id = f"campaign_graph:{campaign_id}"
        payload = json.dumps(graph, separators=(",", ":"))
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO loot
                    (id,campaign_id,loot_type,name,description,content_enc,source_module,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                ON CONFLICT(id) DO UPDATE SET
                  description=EXCLUDED.description,
                  content_enc=EXCLUDED.content_enc,
                  source_module=EXCLUDED.source_module,
                  tags_json=EXCLUDED.tags_json,
                  captured_at=now()
                """,
                graph_id,
                campaign_id,
                "campaign_graph",
                "durable_attack_graph",
                "Sanitized artifact and BloodHound graph snapshot",
                self._enc_val(payload),
                "core.graph",
                json.dumps(["runtime", "safe-metadata"]),
            )

    async def get_campaign_graph(self, campaign_id: str) -> dict[str, Any] | None:
        """Load the safe graph snapshot without returning general decrypted loot."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT content_enc FROM loot
                WHERE id=$1 AND campaign_id=$2 AND loot_type='campaign_graph'
                """,
                f"campaign_graph:{campaign_id}",
                campaign_id,
            )
        if not row or not row["content_enc"]:
            return None
        try:
            decoded = self._dec_val(row["content_enc"])
            parsed = json.loads(decoded) if decoded else None
            return parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            logger.warning("campaign_graph_snapshot_invalid", campaign_id=campaign_id[:8])
            return None

    async def campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        findings = await self.get_findings(campaign_id)
        hosts    = await self.get_hosts(campaign_id)
        creds    = await self.get_credentials(campaign_id)
        loot     = await self.get_loot(campaign_id)
        return {
            "campaign_id":      campaign_id,
            "findings":         findings,
            "finding_count":    len(findings),
            "host_count":       len(hosts),
            "credential_count": len(creds),
            "loot_count":       len(loot),
        }

    # ── Audit ──────────────────────────────────────────────────────────────────

    async def audit(self, actor: str, action: str, detail: str = "",
                    campaign_id: str | None = None, module_id: str | None = None) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_log(campaign_id,actor,action,detail,module_id) VALUES($1,$2,$3,$4,$5)",
                campaign_id, actor, action, detail, module_id,
            )

    # ── Users ──────────────────────────────────────────────────────────────────

    async def create_user(self, username: str, password: str, role: str,
                          created_by: str = "system") -> str:
        user_id = str(uuid.uuid4())
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES($1,$2,$3,$4,$5)",
                user_id, username, hash_password(password), role, created_by,
            )
        logger.info("user_created", username=username, role=role)
        return user_id

    async def get_user(self, username: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE username=$1 AND is_active=1", username
            )
        return self._row_to_dict(row) if row else None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE id=$1 AND is_active=1", user_id
            )
        return self._row_to_dict(row) if row else None

    async def resolve_access_token_principal(
        self,
        subject: str,
        jti: str,
    ) -> dict[str, Any] | None:
        """Resolve current user eligibility and JTI status in one read snapshot."""
        pool = self._pool
        if pool is None:
            raise RuntimeError("Database not connected")
        is_closing = getattr(pool, "is_closing", None)
        if callable(is_closing) and is_closing():
            raise RuntimeError("Database pool is closing")
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT u.id, u.username, u.role
                   FROM users AS u
                   WHERE u.username=$1
                     AND u.is_active=1
                     AND NOT EXISTS (
                         SELECT 1
                         FROM revoked_access_tokens AS rat
                         WHERE rat.jti=$2
                     )""",
                subject,
                jti,
            )
        return self._row_to_dict(row) if row else None

    async def verify_user(self, username: str, password: str) -> dict[str, Any] | None:
        user = await self.get_user(username)
        _DUMMY = "$2b$12$notarealthashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        candidate = user["hashed_password"] if user else _DUMMY
        if not user or not verify_password(password, candidate):
            return None
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE users SET last_login=now() WHERE id=$1", user["id"])
        return user

    async def user_exists(self, username: str) -> bool:
        async with self._pool.acquire() as conn:
            return bool(await conn.fetchval(
                "SELECT 1 FROM users WHERE username=$1", username
            ))

    async def update_password(self, user_id: str, new_hash: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET hashed_password=$1 WHERE id=$2", new_hash, user_id
            )

    async def list_users(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id,username,role,is_active,created_at,last_login FROM users ORDER BY created_at"
            )
        return [self._row_to_dict(r) for r in rows]

    async def ensure_default_admin(self, admin_password: str) -> bool:
        async with self._pool.acquire() as conn:
            n = await conn.fetchval("SELECT COUNT(*) FROM users")
        if n == 0:
            await self.create_user("admin", admin_password, "team_lead", "bootstrap")
            logger.warning("default_admin_created",
                           msg="CHANGE password immediately: POST /auth/change-password")
            return True
        return False

    # ── API Keys ───────────────────────────────────────────────────────────────

    async def create_api_key(self, user_id: str, name: str, scopes: str = "read",
                             expires_days: int | None = None) -> tuple[str, str]:
        raw_key    = "ares_" + secrets.token_urlsafe(40)
        key_prefix = raw_key[:12]
        key_id     = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days) \
                     if expires_days else None
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,scopes,expires_at) "
                "VALUES($1,$2,$3,$4,$5,$6,$7)",
                key_id, user_id, name, hash_password(raw_key), key_prefix, scopes, expires_at,
            )
        return key_id, raw_key

    async def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        if not raw_key.startswith("ares_"):
            return None
        prefix = raw_key[:12]
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT ak.id, ak.key_hash
                   FROM api_keys ak JOIN users u ON ak.user_id=u.id
                   WHERE ak.key_prefix=$1 AND ak.is_active=1
                   AND u.is_active=1
                   AND (ak.expires_at IS NULL OR ak.expires_at > now())""",
                prefix,
            )
        for row in rows:
            d = self._row_to_dict(row)
            if verify_password(raw_key, d["key_hash"]):
                async with self._pool.acquire() as conn:
                    updated = await conn.fetchrow(
                        """UPDATE api_keys AS ak
                           SET last_used=now()
                           FROM users AS u
                           WHERE ak.id=$1
                             AND ak.is_active=1
                             AND (ak.expires_at IS NULL OR ak.expires_at > now())
                             AND u.id=ak.user_id
                             AND u.is_active=1
                           RETURNING ak.id, ak.scopes, u.username, u.role""",
                        d["id"],
                    )
                if updated is None:
                    return None
                return {
                    "username": updated["username"],
                    "role": updated["role"],
                    "auth_type": "api_key",
                    "key_id": updated["id"],
                    "scopes": [updated["scopes"]] if updated["scopes"] else [],
                }
        return None

    async def list_api_keys(self, user_id: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id,name,key_prefix,scopes,is_active,last_used,expires_at,created_at "
                "FROM api_keys WHERE user_id=$1 AND is_active=1 ORDER BY created_at DESC", user_id,
            )
        return [self._row_to_dict(r) for r in rows]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET is_active=0 WHERE id=$1 AND user_id=$2", key_id, user_id
            )
        return True

    # ── Refresh Tokens ─────────────────────────────────────────────────────────

    # ── One-time WebSocket tickets ───────────────────────────────────────────

    def _require_websocket_ticket_pool(self) -> Any:
        if self._pool is None:
            raise RuntimeError("PostgreSQL database is not connected")
        return self._pool

    @staticmethod
    async def _purge_websocket_ticket_rows(connection: Any) -> None:
        await connection.execute(
            "DELETE FROM websocket_tickets WHERE expires_at <= now()"
        )

    async def issue_websocket_ticket(
        self,
        campaign_id: str,
        source: BearerTicketSource | ApiKeyTicketSource,
    ) -> tuple[str, int] | None:
        raw_ticket = generate_websocket_ticket()
        ticket_hash = hash_websocket_ticket(raw_ticket)
        pool = self._require_websocket_ticket_pool()
        issued = False

        async with pool.acquire() as connection:
            async with connection.transaction():
                await self._purge_websocket_ticket_rows(connection)
                if isinstance(source, BearerTicketSource):
                    row = await connection.fetchrow(
                        """
                        INSERT INTO websocket_tickets(
                            ticket_hash, campaign_id, user_id,
                            credential_kind, bearer_subject, bearer_jti,
                            bearer_expires_at, created_at, expires_at
                        )
                        SELECT $1, c.id, u.id, 'bearer', $4, $5, $6,
                               now(), now() + interval '30 seconds'
                        FROM users AS u
                        JOIN campaigns AS c ON c.id=$2
                        WHERE u.id=$3
                          AND u.username=$4
                          AND u.is_active=1
                          AND u.role IN ('team_lead','operator','recon','reporter')
                          AND $6 > now()
                          AND NOT EXISTS (
                              SELECT 1 FROM revoked_access_tokens AS rat
                              WHERE rat.jti=$5
                          )
                          AND (
                              u.role='team_lead'
                              OR c.operator=u.username
                          )
                        RETURNING ticket_hash
                        """,
                        ticket_hash,
                        campaign_id,
                        source.user_id,
                        source.subject,
                        source.jti,
                        source.expires_at,
                    )
                else:
                    row = await connection.fetchrow(
                        """
                        INSERT INTO websocket_tickets(
                            ticket_hash, campaign_id, user_id,
                            credential_kind, api_key_id, required_scope,
                            created_at, expires_at
                        )
                        SELECT $1, c.id, u.id, 'api_key', ak.id, 'read',
                               now(), now() + interval '30 seconds'
                        FROM api_keys AS ak
                        JOIN users AS u ON u.id=ak.user_id
                        JOIN campaigns AS c ON c.id=$2
                        WHERE ak.id=$4
                          AND ak.user_id=$3
                          AND ak.is_active=1
                          AND (ak.expires_at IS NULL OR ak.expires_at > now())
                          AND u.is_active=1
                          AND u.role IN ('team_lead','operator','recon','reporter')
                          AND (
                              regexp_split_to_array(
                                  btrim(COALESCE(ak.scopes, '')),
                                  '[[:space:],]+'
                              ) && ARRAY['read','write','admin']
                          )
                          AND (
                              u.role='team_lead'
                              OR c.operator=u.username
                          )
                        RETURNING ticket_hash
                        """,
                        ticket_hash,
                        campaign_id,
                        source.user_id,
                        source.api_key_id,
                    )
                issued = row is not None

        if not issued:
            return None
        return raw_ticket, WEBSOCKET_TICKET_TTL_SECONDS

    async def consume_websocket_ticket(
        self,
        raw_ticket: str,
        campaign_id: str,
    ) -> ConsumedWebSocketTicket | None:
        if not is_canonical_websocket_ticket(raw_ticket):
            return None

        ticket_hash = hash_websocket_ticket(raw_ticket)
        pool = self._require_websocket_ticket_pool()
        consumed: ConsumedWebSocketTicket | None = None

        async with pool.acquire() as connection:
            async with connection.transaction():
                row = await connection.fetchrow(
                    """
                    UPDATE websocket_tickets
                    SET consumed_at=now()
                    WHERE ticket_hash=$1
                      AND campaign_id=$2
                      AND consumed_at IS NULL
                      AND expires_at > now()
                    RETURNING campaign_id, user_id, credential_kind,
                              bearer_subject, bearer_jti,
                              bearer_expires_at, api_key_id,
                              required_scope
                    """,
                    ticket_hash,
                    campaign_id,
                )
                if row is not None:
                    consumed = ConsumedWebSocketTicket(
                        campaign_id=row["campaign_id"],
                        user_id=row["user_id"],
                        credential_kind=WebSocketTicketCredentialKind(
                            row["credential_kind"]
                        ),
                        bearer_subject=row["bearer_subject"],
                        bearer_jti=row["bearer_jti"],
                        bearer_expires_at=row["bearer_expires_at"],
                        api_key_id=row["api_key_id"],
                        required_scope=row["required_scope"],
                    )

        return consumed

    async def resolve_websocket_ticket_principal(
        self,
        consumed: ConsumedWebSocketTicket,
    ) -> WebSocketTicketPrincipal | None:
        pool = self._require_websocket_ticket_pool()
        async with pool.acquire() as connection:
            if consumed.credential_kind is WebSocketTicketCredentialKind.BEARER:
                row = await connection.fetchrow(
                    """
                    SELECT u.id, u.username, u.role
                    FROM users AS u
                    JOIN campaigns AS c ON c.id=$1
                    WHERE u.id=$2
                      AND u.username=$3
                      AND u.is_active=1
                      AND u.role IN ('team_lead','operator','recon','reporter')
                      AND $4 > now()
                      AND NOT EXISTS (
                          SELECT 1 FROM revoked_access_tokens AS rat
                          WHERE rat.jti=$5
                      )
                      AND (
                          u.role='team_lead'
                          OR c.operator=u.username
                      )
                    """,
                    consumed.campaign_id,
                    consumed.user_id,
                    consumed.bearer_subject,
                    consumed.bearer_expires_at,
                    consumed.bearer_jti,
                )
            else:
                row = await connection.fetchrow(
                    """
                    SELECT u.id, u.username, u.role, ak.id AS api_key_id,
                           ak.scopes
                    FROM api_keys AS ak
                    JOIN users AS u ON u.id=ak.user_id
                    JOIN campaigns AS c ON c.id=$1
                    WHERE ak.id=$3
                      AND ak.user_id=$2
                      AND ak.is_active=1
                      AND (ak.expires_at IS NULL OR ak.expires_at > now())
                      AND u.is_active=1
                      AND u.role IN ('team_lead','operator','recon','reporter')
                      AND (
                          regexp_split_to_array(
                              btrim(COALESCE(ak.scopes, '')),
                              '[[:space:],]+'
                          ) && ARRAY['read','write','admin']
                      )
                      AND (
                          u.role='team_lead'
                          OR c.operator=u.username
                      )
                    """,
                    consumed.campaign_id,
                    consumed.user_id,
                    consumed.api_key_id,
                )

        if row is None:
            return None
        if not is_valid_websocket_principal_role(row["role"]):
            return None
        if consumed.credential_kind is WebSocketTicketCredentialKind.BEARER:
            return WebSocketTicketPrincipal(
                user_id=row["id"],
                username=row["username"],
                role=row["role"],
                credential_kind=WebSocketTicketCredentialKind.BEARER,
            )
        scopes = normalize_api_key_scopes(row["scopes"])
        if not set(scopes).intersection({"read", "write", "admin"}):
            return None
        return WebSocketTicketPrincipal(
            user_id=row["id"],
            username=row["username"],
            role=row["role"],
            credential_kind=WebSocketTicketCredentialKind.API_KEY,
            api_key_id=row["api_key_id"],
            api_key_scopes=scopes,
        )

    async def purge_expired_websocket_tickets(self) -> int:
        pool = self._require_websocket_ticket_pool()
        async with pool.acquire() as connection:
            async with connection.transaction():
                result = await connection.execute(
                    "DELETE FROM websocket_tickets WHERE expires_at <= now()"
                )
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    # ── Refresh tokens ───────────────────────────────────────────────────────

    async def create_refresh_token(self, user_id: str, expires_days: int = 30) -> str:
        raw_token  = secrets.token_urlsafe(48)                          # returned to client
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()     # stored in DB
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await _acquire_refresh_token_user_lock(conn, user_id)
                await conn.execute(
                    "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES($1,$2,$3)",
                    token_hash, user_id, expires_at,   # store hash, not raw
                )
        return raw_token   # client gets raw token; DB stores only SHA-256 hash

    async def rotate_refresh_token(self, old_token: str) -> tuple[dict | None, str | None]:
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()   # look up by hash
        user: dict[str, Any] | None = None
        new_raw: str | None = None
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                user_id = await conn.fetchval(
                    "SELECT user_id FROM refresh_tokens WHERE id=$1",
                    old_hash,
                )
                if user_id is None:
                    return None, None

                await _acquire_refresh_token_user_lock(conn, user_id)
                row = await conn.fetchrow(
                    """UPDATE refresh_tokens AS rt
                       SET is_revoked=1, used_at=now()
                       FROM users AS u
                       WHERE rt.id=$1
                         AND rt.user_id=$2
                         AND rt.is_revoked=0
                         AND rt.expires_at > now()
                         AND u.id=rt.user_id
                         AND u.is_active=1
                       RETURNING u.id AS uid, u.username, u.role""",
                    old_hash,
                    user_id,
                )
                if row is None:
                    return None, None

                new_raw = secrets.token_urlsafe(48)
                new_hash = hashlib.sha256(new_raw.encode()).hexdigest()
                expires_at = datetime.now(timezone.utc) + timedelta(days=30)
                await conn.execute(
                    "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES($1,$2,$3)",
                    new_hash, user_id, expires_at,   # store hash
                )
                user = {
                    "id": row["uid"],
                    "username": row["username"],
                    "role": row["role"],
                }
        if user is None or new_raw is None:
            return None, None
        return user, new_raw   # return raw to client

    async def revoke_access_token(self, jti: str, user_id: str, expires_at: str) -> None:
        parsed_expires_at = _parse_postgres_timestamptz(expires_at)
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO revoked_access_tokens(jti,user_id,expires_at) VALUES($1,$2,$3) "
                "ON CONFLICT(jti) DO NOTHING",
                jti, user_id, parsed_expires_at,
            )
            await conn.execute(
                "DELETE FROM revoked_access_tokens WHERE expires_at < now()"
            )

    async def is_access_token_revoked(self, jti: str) -> bool:
        async with self._pool.acquire() as conn:
            return bool(await conn.fetchval(
                "SELECT 1 FROM revoked_access_tokens WHERE jti=$1", jti
            ))

    async def revoke_all_refresh_tokens(self, user_id: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await _acquire_refresh_token_user_lock(conn, user_id)
                await conn.execute(
                    "UPDATE refresh_tokens SET is_revoked=1 WHERE user_id=$1", user_id
                )

    async def purge_expired_tokens(self) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM refresh_tokens WHERE is_revoked=1 OR expires_at < now() - interval '7 days'"
            )
        await self.purge_expired_websocket_tickets()
        # asyncpg returns "DELETE N" as a string
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    # ── Bypass outcome tracking (cross-session EDR learning) ──────────────

    async def save_bypass_outcome(
        self,
        technique_id: str,
        edr_vendor:   str,
        edr_version:  str,
        success:      bool,
        campaign_id:  str,
        notes:        str = "",
    ) -> None:
        """Persist bypass technique outcome for cross-session learning."""
        import time as _time
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO bypass_outcomes
                       (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                    technique_id, edr_vendor, edr_version,
                    int(success), campaign_id, notes[:500], _time.time(),
                )
        except Exception:
            await self._ensure_bypass_outcomes_table()
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO bypass_outcomes
                       (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                    technique_id, edr_vendor, edr_version,
                    int(success), campaign_id, notes[:500], _time.time(),
                )

    async def get_bypass_success_rate(
        self,
        technique_id: str,
        edr_vendor:   str,
        min_samples:  int = 3,
    ) -> float | None:
        """Return historical success rate for a bypass technique against an EDR vendor."""
        import time as _time
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """SELECT COUNT(*) as total, COALESCE(SUM(success), 0) as successes
                       FROM bypass_outcomes
                       WHERE technique_id = $1 AND edr_vendor = $2
                       AND ts > $3""",
                    technique_id, edr_vendor, _time.time() - 7_776_000,
                )
            if not row or row["total"] < min_samples:
                return None
            return round(row["successes"] / row["total"], 3)
        except Exception:
            return None

    async def _ensure_bypass_outcomes_table(self) -> None:
        """Create bypass_outcomes table if it doesn't exist."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS bypass_outcomes (
                   id           SERIAL PRIMARY KEY,
                   technique_id TEXT    NOT NULL,
                   edr_vendor   TEXT    NOT NULL,
                   edr_version  TEXT    DEFAULT '',
                   success      INTEGER NOT NULL,
                   campaign_id  TEXT    DEFAULT '',
                   notes        TEXT    DEFAULT '',
                   ts           DOUBLE PRECISION NOT NULL
                )"""
            )

    async def checkpoint_wal(self) -> None:
        """No-op for PostgreSQL — WAL is managed by the server."""

    async def export_json(self, output_path: str | None = None) -> str:
        """Export all campaigns + findings to JSON (same interface as SQLite backend)."""
        import json as _json
        from pathlib import Path
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not output_path:
            backup_dir = Path.home() / ".ares" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(backup_dir / f"ares_export_{ts}.json")

        async with self._pool.acquire() as conn:
            campaigns = [self._row_to_dict(r)
                         for r in await conn.fetch("SELECT * FROM campaigns ORDER BY created_at DESC")]
        for c in campaigns:
            cid = c["id"]
            async with self._pool.acquire() as conn:
                c["_findings"] = [self._row_to_dict(r)
                                  for r in await conn.fetch(
                                      "SELECT * FROM findings WHERE campaign_id=$1 ORDER BY discovered_at DESC",
                                      cid)]
                c["_hosts"]    = [self._row_to_dict(r)
                                  for r in await conn.fetch(
                                      "SELECT * FROM hosts WHERE campaign_id=$1 ORDER BY first_seen", cid)]

        export = {"export_version": "1.0", "exported_at": ts, "campaigns": campaigns}
        with open(output_path, "w") as fh:
            _json.dump(export, fh, indent=2, default=str)
        logger.info("pg_export_complete", path=output_path, campaigns=len(campaigns))
        return output_path
