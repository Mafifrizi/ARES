"""Add revoked_access_tokens table for JWT early revocation (logout)

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-04 00:00:00

This table was present in schema.py CREATE TABLE IF NOT EXISTS path since v0.5
but was never added to the alembic migration chain.
All deployments using alembic upgrade head MUST run this migration.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision:      str       = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    op.create_table(
        "revoked_access_tokens",
        sa.Column("jti",        sa.Text, primary_key=True),
        sa.Column("user_id",    sa.Text, nullable=False),
        sa.Column("revoked_at", sa.Text, nullable=False,
                  server_default=sa.text("datetime('now')")),
        sa.Column("expires_at", sa.Text, nullable=False),
    )
    op.create_index("idx_rat_expires", "revoked_access_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_rat_expires", "revoked_access_tokens")
    op.drop_table("revoked_access_tokens")
