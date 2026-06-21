"""Add rate_limit_events table for audit/analytics

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-03 00:00:00
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision:      str       = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    op.create_table("rate_limit_events",
        sa.Column("id",         sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ip_address", sa.Text, nullable=False),
        sa.Column("bucket",     sa.Text, nullable=False),
        sa.Column("username",   sa.Text),
        sa.Column("blocked",    sa.Integer, nullable=False, server_default="0"),
        sa.Column("timestamp",  sa.Text, nullable=False, server_default=sa.text("datetime('now')")),
    )
    op.create_index("idx_rle_ip",        "rate_limit_events", ["ip_address"])
    op.create_index("idx_rle_timestamp", "rate_limit_events", ["timestamp"])
    op.create_index("idx_rle_blocked",   "rate_limit_events", ["blocked"])


def downgrade() -> None:
    op.drop_table("rate_limit_events")
