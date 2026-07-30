"""Add portable access-token revocation storage.

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-04 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
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
        "revoked_access_tokens",
        sa.Column("jti", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column(
            "revoked_at",
            timestamp,
            nullable=False,
            server_default=database_now,
        ),
        sa.Column("expires_at", timestamp, nullable=False),
        *(
            (
                sa.CheckConstraint(
                    "isfinite(revoked_at)",
                    name="ck_revoked_access_tokens_revoked_at_finite",
                ),
                sa.CheckConstraint(
                    "isfinite(expires_at)",
                    name="ck_revoked_access_tokens_expires_at_finite",
                ),
            )
            if dialect == "postgresql"
            else ()
        ),
    )
    op.create_index(
        "idx_rat_expires", "revoked_access_tokens", ["expires_at"]
    )


def downgrade() -> None:
    _timestamp_contract()
    op.drop_table("revoked_access_tokens")
