"""Add trace_id column to findings table

Revision ID: 0005
Revises: 0004
Create Date: 2025-01-05 00:00:00

trace_id was present in schema.py (CREATE TABLE IF NOT EXISTS) since v0.5
but was missing from the Alembic migration chain.
Deployments using `alembic upgrade head` from scratch will get this
column via migration 0001 (re-run safe via IF NOT EXISTS path),
but existing deployments need this ALTER TABLE to add the column.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa


revision:      str       = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_columns = {col["name"] for col in inspector.get_columns("findings")}
    if "trace_id" not in existing_columns:
        # Use batch_alter_table for SQLite compatibility (SQLite doesn't support
        # ADD COLUMN with constraints in all versions)
        with op.batch_alter_table("findings") as batch_op:
            batch_op.add_column(
                sa.Column("trace_id", sa.Text, nullable=False, server_default="")
            )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("trace_id")
