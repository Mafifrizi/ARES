"""Create the portable ARES baseline schema.

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

_DIALECT_ERROR = "Unsupported migration dialect"


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in {"sqlite", "postgresql"}:
        raise RuntimeError(_DIALECT_ERROR)
    return name


def _timestamp_type(dialect: str) -> sa.types.TypeEngine:
    if dialect == "postgresql":
        return sa.DateTime(timezone=True)
    return sa.Text()


def _database_now(dialect: str) -> sa.sql.elements.TextClause:
    if dialect == "postgresql":
        return sa.text("now()")
    return sa.text("datetime('now')")


def _finite_timestamp(
    dialect: str,
    column: str,
    name: str,
    *,
    nullable: bool = False,
) -> tuple[sa.CheckConstraint, ...]:
    if dialect != "postgresql":
        return ()
    expression = (
        f"{column} IS NULL OR isfinite({column})"
        if nullable
        else f"isfinite({column})"
    )
    return (sa.CheckConstraint(expression, name=name),)


def upgrade() -> None:
    dialect = _dialect()
    timestamp = _timestamp_type(dialect)
    database_now = _database_now(dialect)

    if dialect == "sqlite":
        op.create_table(
            "schema_version",
            sa.Column("version", sa.Integer(), primary_key=True),
            sa.Column(
                "applied_at",
                sa.Text(),
                nullable=False,
                server_default=database_now,
            ),
        )

    op.create_table(
        "campaigns",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "client", sa.Text(), nullable=False, server_default="Internal"
        ),
        sa.Column(
            "operator", sa.Text(), nullable=False, server_default="unknown"
        ),
        sa.Column(
            "noise_profile",
            sa.Text(),
            nullable=False,
            server_default="stealth",
        ),
        sa.Column(
            "status", sa.Text(), nullable=False, server_default="created"
        ),
        sa.Column(
            "scope_json", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "targets_json", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column("notes", sa.Text(), server_default=""),
        sa.Column(
            "created_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.Column(
            "updated_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "created_at",
            "ck_campaigns_created_at_finite",
        ),
        *_finite_timestamp(
            dialect,
            "updated_at",
            "ck_campaigns_updated_at_finite",
        ),
    )

    op.create_table(
        "module_runs",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_module_runs_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("module_id", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column(
            "success", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "duration_ms", sa.Float(), nullable=False, server_default="0.0"
        ),
        sa.Column(
            "completed_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "completed_at",
            "ck_module_runs_completed_at_finite",
        ),
    )
    op.create_index(
        "idx_module_runs_campaign", "module_runs", ["campaign_id"]
    )
    op.create_index(
        "idx_module_runs_completed", "module_runs", ["completed_at"]
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_findings_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("module_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column(
            "confidence", sa.Float(), nullable=False, server_default="1.0"
        ),
        sa.Column("mitre_technique", sa.Text()),
        sa.Column("mitre_tactic", sa.Text()),
        sa.Column(
            "cvss_score", sa.Float(), nullable=False, server_default="0.0"
        ),
        sa.Column(
            "cvss_vector", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column(
            "evidence_json", sa.Text(), nullable=False, server_default="{}"
        ),
        sa.Column("remediation", sa.Text(), server_default=""),
        sa.Column("host", sa.Text()),
        sa.Column(
            "validated", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "false_positive",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "discovered_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "discovered_at",
            "ck_findings_discovered_at_finite",
        ),
    )
    op.create_index("idx_findings_campaign", "findings", ["campaign_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_index("idx_findings_fp", "findings", ["false_positive"])
    op.create_index("idx_findings_mitre", "findings", ["mitre_technique"])

    op.create_table(
        "hosts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_hosts_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("ip_address", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text()),
        sa.Column("fqdn", sa.Text()),
        sa.Column("os", sa.Text()),
        sa.Column("os_version", sa.Text()),
        sa.Column("domain", sa.Text()),
        sa.Column("is_dc", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "open_ports_json", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "tags_json", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "first_seen",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.Column(
            "last_seen",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "first_seen",
            "ck_hosts_first_seen_finite",
        ),
        *_finite_timestamp(
            dialect,
            "last_seen",
            "ck_hosts_last_seen_finite",
        ),
        sa.UniqueConstraint(
            "campaign_id",
            "ip_address",
            name="uq_hosts_campaign_ip",
        ),
    )
    op.create_index("idx_hosts_campaign", "hosts", ["campaign_id"])
    op.create_index("idx_hosts_ip", "hosts", ["ip_address"])
    op.create_index("idx_hosts_domain", "hosts", ["domain"])

    op.create_table(
        "credentials",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_credentials_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            sa.Text(),
            sa.ForeignKey(
                "hosts.id",
                name="fk_credentials_host",
                ondelete="SET NULL",
            ),
        ),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("secret_enc", sa.Text()),
        sa.Column("cred_type", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text()),
        sa.Column("source_module", sa.Text()),
        sa.Column("notes", sa.Text(), server_default=""),
        sa.Column(
            "cracked", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("cracked_value", sa.Text()),
        sa.Column(
            "captured_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "captured_at",
            "ck_credentials_captured_at_finite",
        ),
    )
    op.create_index("idx_creds_campaign", "credentials", ["campaign_id"])
    op.create_index("idx_creds_username", "credentials", ["username"])
    op.create_index("idx_creds_type", "credentials", ["cred_type"])

    op.create_table(
        "loot",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_loot_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            sa.Text(),
            sa.ForeignKey(
                "hosts.id",
                name="fk_loot_host",
                ondelete="SET NULL",
            ),
        ),
        sa.Column("loot_type", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("content_enc", sa.Text()),
        sa.Column("size_bytes", sa.Integer(), server_default="0"),
        sa.Column("path_on_target", sa.Text()),
        sa.Column("source_module", sa.Text()),
        sa.Column(
            "tags_json", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "captured_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "captured_at",
            "ck_loot_captured_at_finite",
        ),
    )
    op.create_index("idx_loot_campaign", "loot", ["campaign_id"])
    op.create_index("idx_loot_type", "loot", ["loot_type"])

    op.create_table(
        "audit_log",
        sa.Column(
            "id", sa.Integer(), primary_key=True, autoincrement=True
        ),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_audit_campaign",
                ondelete="SET NULL",
            ),
        ),
        sa.Column(
            "actor", sa.Text(), nullable=False, server_default="system"
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), server_default=""),
        sa.Column("module_id", sa.Text()),
        sa.Column(
            "timestamp",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "timestamp",
            "ck_audit_log_timestamp_finite",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("idx_audit_campaign", "audit_log", ["campaign_id"])
    op.create_index("idx_audit_actor", "audit_log", ["actor"])
    op.create_index("idx_audit_action", "audit_log", ["action"])

    op.create_table(
        "users",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column(
            "role", sa.Text(), nullable=False, server_default="reporter"
        ),
        sa.Column(
            "is_active", sa.Integer(), nullable=False, server_default="1"
        ),
        sa.Column(
            "created_by", sa.Text(), nullable=False, server_default="system"
        ),
        sa.Column(
            "created_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.Column("last_login", timestamp),
        *_finite_timestamp(
            dialect,
            "created_at",
            "ck_users_created_at_finite",
        ),
        *_finite_timestamp(
            dialect,
            "last_login",
            "ck_users_last_login_finite",
            nullable=True,
        ),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("idx_users_username", "users", ["username"])
    op.create_index("idx_users_role", "users", ["role"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey(
                "users.id",
                name="fk_api_keys_user",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column("key_prefix", sa.Text(), nullable=False),
        sa.Column(
            "scopes", sa.Text(), nullable=False, server_default="read"
        ),
        sa.Column(
            "is_active", sa.Integer(), nullable=False, server_default="1"
        ),
        sa.Column("last_used", timestamp),
        sa.Column("expires_at", timestamp),
        sa.Column(
            "created_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        *_finite_timestamp(
            dialect,
            "last_used",
            "ck_api_keys_last_used_finite",
            nullable=True,
        ),
        *_finite_timestamp(
            dialect,
            "expires_at",
            "ck_api_keys_expires_at_finite",
            nullable=True,
        ),
        *_finite_timestamp(
            dialect,
            "created_at",
            "ck_api_keys_created_at_finite",
        ),
    )
    op.create_index("idx_apikeys_user", "api_keys", ["user_id"])
    op.create_index("idx_apikeys_prefix", "api_keys", ["key_prefix"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey(
                "users.id",
                name="fk_refresh_tokens_user",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "is_revoked", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("expires_at", timestamp, nullable=False),
        sa.Column(
            "created_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.Column("used_at", timestamp),
        *_finite_timestamp(
            dialect,
            "expires_at",
            "ck_refresh_tokens_expires_at_finite",
        ),
        *_finite_timestamp(
            dialect,
            "created_at",
            "ck_refresh_tokens_created_at_finite",
        ),
        *_finite_timestamp(
            dialect,
            "used_at",
            "ck_refresh_tokens_used_at_finite",
            nullable=True,
        ),
    )
    op.create_index("idx_refresh_user", "refresh_tokens", ["user_id"])
    op.create_index("idx_refresh_exp", "refresh_tokens", ["expires_at"])


def downgrade() -> None:
    dialect = _dialect()
    for table_name in (
        "refresh_tokens",
        "api_keys",
        "users",
        "audit_log",
        "loot",
        "credentials",
        "hosts",
        "findings",
        "module_runs",
        "campaigns",
    ):
        op.drop_table(table_name)
    if dialect == "sqlite":
        op.drop_table("schema_version")
