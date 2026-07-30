"""Add portable rate-limit audit storage.

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-03 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def _timestamp_contract() -> tuple[
    sa.types.TypeEngine,
    sa.sql.elements.TextClause,
]:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        return sa.Text(), sa.text("datetime('now')")
    if dialect == "postgresql":
        return sa.DateTime(timezone=True), sa.text("now()")
    raise RuntimeError("Unsupported migration dialect")


def upgrade() -> None:
    timestamp, database_now = _timestamp_contract()
    dialect = op.get_bind().dialect.name
    op.create_table(
        "rate_limit_events",
        sa.Column(
            "id", sa.Integer(), primary_key=True, autoincrement=True
        ),
        sa.Column("ip_address", sa.Text(), nullable=False),
        sa.Column("bucket", sa.Text(), nullable=False),
        sa.Column("username", sa.Text()),
        sa.Column(
            "blocked", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "timestamp",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.CheckConstraint(
            "blocked IN (0, 1)",
            name="ck_rate_limit_events_blocked_bool",
        ),
        *(
            (
                sa.CheckConstraint(
                    "isfinite(timestamp)",
                    name="ck_rate_limit_events_timestamp_finite",
                ),
            )
            if dialect == "postgresql"
            else ()
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("idx_rle_ip", "rate_limit_events", ["ip_address"])
    op.create_index(
        "idx_rle_timestamp", "rate_limit_events", ["timestamp"]
    )
    op.create_index("idx_rle_blocked", "rate_limit_events", ["blocked"])


def downgrade() -> None:
    _timestamp_contract()
    op.drop_table("rate_limit_events")
