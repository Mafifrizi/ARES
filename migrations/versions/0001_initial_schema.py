"""Initial schema — tables from schema.py v5

Revision ID: 0001
Revises: 
Create Date: 2025-01-01 00:00:00
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision:      str       = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    op.execute("PRAGMA journal_mode = WAL")
    op.execute("PRAGMA foreign_keys = ON")

    op.create_table("campaigns",
        sa.Column("id",            sa.Text, primary_key=True),
        sa.Column("name",          sa.Text, nullable=False),
        sa.Column("client",        sa.Text, nullable=False, server_default="Internal"),
        sa.Column("operator",      sa.Text, nullable=False, server_default="unknown"),
        sa.Column("noise_profile", sa.Text, nullable=False, server_default="stealth"),
        sa.Column("status",        sa.Text, nullable=False, server_default="created"),
        sa.Column("scope_json",    sa.Text, nullable=False, server_default="[]"),
        sa.Column("targets_json",  sa.Text, nullable=False, server_default="[]"),
        sa.Column("notes",         sa.Text, server_default=""),
        sa.Column("created_at",    sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
        sa.Column("updated_at",    sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )

    op.create_table("findings",
        sa.Column("id",              sa.Text, primary_key=True),
        sa.Column("campaign_id",     sa.Text, nullable=False),
        sa.Column("module_id",       sa.Text, nullable=False),
        sa.Column("title",           sa.Text, nullable=False),
        sa.Column("description",     sa.Text, nullable=False),
        sa.Column("severity",        sa.Text, nullable=False),
        sa.Column("cvss_score",      sa.Float, server_default="0.0"),
        sa.Column("cvss_vector",     sa.Text, server_default=""),
        sa.Column("confidence",      sa.Float, nullable=False, server_default="1.0"),
        sa.Column("mitre_technique", sa.Text),
        sa.Column("mitre_tactic",    sa.Text),
        sa.Column("evidence_json",   sa.Text, nullable=False, server_default="{}"),
        sa.Column("remediation",     sa.Text, server_default=""),
        sa.Column("host",            sa.Text),
        sa.Column("validated",       sa.Integer, nullable=False, server_default="0"),
        sa.Column("false_positive",  sa.Integer, nullable=False, server_default="0"),
        sa.Column("discovered_at",   sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_findings_campaign",   "findings", ["campaign_id"])
    op.create_index("idx_findings_severity",   "findings", ["severity"])
    op.create_index("idx_findings_fp",         "findings", ["false_positive"])
    op.create_index("idx_findings_validated",  "findings", ["validated"])
    op.create_index("idx_findings_mitre",      "findings", ["mitre_technique"])

    op.create_table("hosts",
        sa.Column("id",              sa.Text, primary_key=True),
        sa.Column("campaign_id",     sa.Text, nullable=False),
        sa.Column("ip_address",      sa.Text, nullable=False),
        sa.Column("hostname",        sa.Text),
        sa.Column("fqdn",            sa.Text),
        sa.Column("os",              sa.Text),
        sa.Column("os_version",      sa.Text),
        sa.Column("domain",          sa.Text),
        sa.Column("is_dc",           sa.Integer, nullable=False, server_default="0"),
        sa.Column("open_ports_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("tags_json",       sa.Text, nullable=False, server_default="[]"),
        sa.Column("first_seen",      sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
        sa.Column("last_seen",       sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
        sa.UniqueConstraint("campaign_id", "ip_address"),
    )
    op.create_index("idx_hosts_campaign", "hosts", ["campaign_id"])
    op.create_index("idx_hosts_ip",       "hosts", ["ip_address"])
    op.create_index("idx_hosts_domain",   "hosts", ["domain"])

    op.create_table("credentials",
        sa.Column("id",            sa.Text, primary_key=True),
        sa.Column("campaign_id",   sa.Text, nullable=False),
        sa.Column("host_id",       sa.Text),
        sa.Column("username",      sa.Text, nullable=False),
        sa.Column("secret_enc",    sa.Text),
        sa.Column("cred_type",     sa.Text, nullable=False),
        sa.Column("domain",        sa.Text),
        sa.Column("source_module", sa.Text),
        sa.Column("notes",         sa.Text, server_default=""),
        sa.Column("cracked",       sa.Integer, nullable=False, server_default="0"),
        sa.Column("cracked_value", sa.Text),
        sa.Column("captured_at",   sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_creds_campaign", "credentials", ["campaign_id"])
    op.create_index("idx_creds_username", "credentials", ["username"])
    op.create_index("idx_creds_type",     "credentials", ["cred_type"])

    op.create_table("loot",
        sa.Column("id",             sa.Text, primary_key=True),
        sa.Column("campaign_id",    sa.Text, nullable=False),
        sa.Column("host_id",        sa.Text),
        sa.Column("loot_type",      sa.Text, nullable=False),
        sa.Column("name",           sa.Text, nullable=False),
        sa.Column("description",    sa.Text, server_default=""),
        sa.Column("content_enc",    sa.Text),
        sa.Column("size_bytes",     sa.Integer, server_default="0"),
        sa.Column("path_on_target", sa.Text),
        sa.Column("source_module",  sa.Text),
        sa.Column("tags_json",      sa.Text, nullable=False, server_default="[]"),
        sa.Column("captured_at",    sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_loot_campaign", "loot", ["campaign_id"])
    op.create_index("idx_loot_type",     "loot", ["loot_type"])

    op.create_table("audit_log",
        sa.Column("id",          sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("campaign_id", sa.Text),
        sa.Column("actor",       sa.Text, nullable=False, server_default="system"),
        sa.Column("action",      sa.Text, nullable=False),
        sa.Column("detail",      sa.Text, server_default=""),
        sa.Column("module_id",   sa.Text),
        sa.Column("timestamp",   sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_audit_campaign", "audit_log", ["campaign_id"])
    op.create_index("idx_audit_actor",    "audit_log", ["actor"])
    op.create_index("idx_audit_action",   "audit_log", ["action"])

    op.create_table("users",
        sa.Column("id",              sa.Text, primary_key=True),
        sa.Column("username",        sa.Text, nullable=False, unique=True),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("role",            sa.Text, nullable=False, server_default="reporter"),
        sa.Column("is_active",       sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_by",      sa.Text, nullable=False, server_default="system"),
        sa.Column("created_at",      sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
        sa.Column("last_login",      sa.Text),
    )
    op.create_index("idx_users_username", "users", ["username"])
    op.create_index("idx_users_role",     "users", ["role"])

    op.create_table("api_keys",
        sa.Column("id",         sa.Text, primary_key=True),
        sa.Column("user_id",    sa.Text, nullable=False),
        sa.Column("name",       sa.Text, nullable=False),
        sa.Column("key_hash",   sa.Text, nullable=False),
        sa.Column("key_prefix", sa.Text, nullable=False),
        sa.Column("scopes",     sa.Text, nullable=False, server_default="read"),
        sa.Column("is_active",  sa.Integer, nullable=False, server_default="1"),
        sa.Column("last_used",  sa.Text),
        sa.Column("expires_at", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_apikeys_user",   "api_keys", ["user_id"])
    op.create_index("idx_apikeys_prefix", "api_keys", ["key_prefix"])

    op.create_table("refresh_tokens",
        sa.Column("id",         sa.Text, primary_key=True),
        sa.Column("user_id",    sa.Text, nullable=False),
        sa.Column("is_revoked", sa.Integer, nullable=False, server_default="0"),
        sa.Column("expires_at", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
        sa.Column("used_at",    sa.Text),
    )
    op.create_index("idx_refresh_user", "refresh_tokens", ["user_id"])
    op.create_index("idx_refresh_exp",  "refresh_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_findings_validated", "findings")
    for t in ("refresh_tokens", "api_keys", "users", "audit_log",
              "loot", "credentials", "hosts", "findings", "campaigns"):
        op.drop_table(t)
