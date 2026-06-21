"""Add CVSS score and vector to findings table

Revision ID: 0002
Revises: 0001
Create Date: 2025-01-02 00:00:00
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision:      str       = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on:    str | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing_columns = {col["name"] for col in inspector.get_columns("findings")}
    columns_to_add = [
        ("cvss_score", sa.Column("cvss_score", sa.Float, server_default="0.0")),
        ("cvss_vector", sa.Column("cvss_vector", sa.Text, server_default="")),
        ("trace_id", sa.Column("trace_id", sa.Text, server_default="")),
    ]
    missing_columns = [
        column for name, column in columns_to_add if name not in existing_columns
    ]
    if missing_columns:
        with op.batch_alter_table("findings") as batch_op:
            for column in missing_columns:
                batch_op.add_column(column)

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("findings")}
    if "idx_findings_cvss" not in existing_indexes:
        op.create_index("idx_findings_cvss", "findings", ["cvss_score"])


def downgrade() -> None:
    op.drop_index("idx_findings_cvss", "findings")
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("trace_id")
        batch_op.drop_column("cvss_vector")
        batch_op.drop_column("cvss_score")
