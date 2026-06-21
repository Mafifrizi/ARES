"""Rename cracked_value to cracked_value_enc in credentials table

Revision ID: 0006
Revises: 0005
Create Date: 2026-03-22 00:00:00

BUG-09 fix: schema.py uses cracked_value_enc (Fernet-encrypted) but
migration 0001 created the column as cracked_value (unencrypted name).

This migration renames the column so alembic-managed deployments match
the CREATE_TABLES fallback schema in schema.py.

SQLite does not support RENAME COLUMN before version 3.25.0 (2018-09-15).
We use a safe copy-transform for compatibility with older SQLite versions.
PostgreSQL supports ALTER TABLE ... RENAME COLUMN natively.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection


revision:      str       = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        # PostgreSQL — clean rename
        op.alter_column(
            "credentials",
            "cracked_value",
            new_column_name="cracked_value_enc",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
    else:
        # SQLite — does not support RENAME COLUMN before 3.25.0.
        # Check if column already has the correct name (idempotent).
        insp = reflection.Inspector.from_engine(bind)
        cols = [c["name"] for c in insp.get_columns("credentials")]

        if "cracked_value_enc" in cols:
            # Already renamed (e.g. deployed from CREATE_TABLES) — nothing to do
            return

        if "cracked_value" not in cols:
            # Neither column exists — add the correct one
            op.add_column(
                "credentials",
                sa.Column("cracked_value_enc", sa.Text(), nullable=True),
            )
            return

        # Rename via copy: add new col, copy data, drop old col.
        # This is safe — cracked_value was never encrypted in old schema,
        # so values (if any) are already plaintext and will remain as-is.
        with op.batch_alter_table("credentials") as batch_op:
            batch_op.add_column(
                sa.Column("cracked_value_enc", sa.Text(), nullable=True)
            )

        bind.execute(sa.text(
            "UPDATE credentials SET cracked_value_enc = cracked_value "
            "WHERE cracked_value IS NOT NULL"
        ))

        with op.batch_alter_table("credentials") as batch_op:
            batch_op.drop_column("cracked_value")


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.alter_column(
            "credentials",
            "cracked_value_enc",
            new_column_name="cracked_value",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
    else:
        insp = reflection.Inspector.from_engine(bind)
        cols = [c["name"] for c in insp.get_columns("credentials")]
        if "cracked_value" in cols:
            return
        with op.batch_alter_table("credentials") as batch_op:
            batch_op.add_column(
                sa.Column("cracked_value", sa.Text(), nullable=True)
            )
        bind.execute(sa.text(
            "UPDATE credentials SET cracked_value = cracked_value_enc "
            "WHERE cracked_value_enc IS NOT NULL"
        ))
        with op.batch_alter_table("credentials") as batch_op:
            batch_op.drop_column("cracked_value_enc")
