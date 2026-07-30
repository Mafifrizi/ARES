"""Reconcile CVSS fields and introduce finding trace metadata.

Revision ID: 0002
Revises: 0001
Create Date: 2025-01-02 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None

_CATALOG_ERROR = "Incompatible findings catalog for migration 0002"
_DIALECT_ERROR = "Unsupported migration dialect"


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in {"sqlite", "postgresql"}:
        raise RuntimeError(_DIALECT_ERROR)
    return name


def _columns() -> dict[str, dict[str, object]]:
    inspector = sa.inspect(op.get_bind())
    if "findings" not in inspector.get_table_names():
        raise RuntimeError(_CATALOG_ERROR)
    return {
        str(column["name"]): column
        for column in inspector.get_columns("findings")
    }


def _validate_existing(columns: dict[str, dict[str, object]]) -> None:
    score = columns.get("cvss_score")
    if score is not None and not isinstance(score["type"], sa.Float):
        raise RuntimeError(_CATALOG_ERROR)
    for name in ("cvss_vector", "trace_id"):
        column = columns.get(name)
        if column is not None and not isinstance(
            column["type"], (sa.Text, sa.String)
        ):
            raise RuntimeError(_CATALOG_ERROR)


def _harden_existing(
    dialect: str,
    columns: dict[str, dict[str, object]],
) -> None:
    specifications = (
        ("cvss_score", sa.Float(), "0.0"),
        ("cvss_vector", sa.Text(), ""),
    )
    for name, column_type, default in specifications:
        column = columns[name]
        if bool(column.get("nullable", True)):
            if name == "cvss_score":
                op.execute(
                    sa.text(
                        "UPDATE findings SET cvss_score=0.0 "
                        "WHERE cvss_score IS NULL"
                    )
                )
            else:
                op.execute(
                    sa.text(
                        "UPDATE findings SET cvss_vector='' "
                        "WHERE cvss_vector IS NULL"
                    )
                )
        if dialect == "sqlite":
            with op.batch_alter_table("findings") as batch_op:
                batch_op.alter_column(
                    name,
                    existing_type=column_type,
                    nullable=False,
                    server_default=default,
                )
        else:
            op.alter_column(
                "findings",
                name,
                existing_type=column_type,
                nullable=False,
                server_default=default,
            )


def _ensure_cvss_index() -> None:
    indexes = {
        str(index["name"]): index
        for index in sa.inspect(op.get_bind()).get_indexes("findings")
    }
    current = indexes.get("idx_findings_cvss")
    if current is None:
        op.create_index("idx_findings_cvss", "findings", ["cvss_score"])
        return
    if current.get("column_names") != ["cvss_score"] or bool(
        current.get("unique", False)
    ):
        raise RuntimeError(_CATALOG_ERROR)


def upgrade() -> None:
    dialect = _dialect()
    columns = _columns()
    _validate_existing(columns)
    missing = []
    if "cvss_score" not in columns:
        missing.append(
            sa.Column(
                "cvss_score",
                sa.Float(),
                nullable=False,
                server_default="0.0",
            )
        )
    if "cvss_vector" not in columns:
        missing.append(
            sa.Column(
                "cvss_vector",
                sa.Text(),
                nullable=False,
                server_default="",
            )
        )
    if "trace_id" not in columns:
        missing.append(
            sa.Column(
                "trace_id",
                sa.Text(),
                nullable=True,
                server_default="",
            )
        )
    if missing:
        if dialect == "sqlite":
            with op.batch_alter_table("findings") as batch_op:
                for column in missing:
                    batch_op.add_column(column)
        else:
            for column in missing:
                op.add_column("findings", column)

    reconciled = _columns()
    _validate_existing(reconciled)
    _harden_existing(dialect, reconciled)
    _ensure_cvss_index()


def downgrade() -> None:
    dialect = _dialect()
    columns = _columns()
    _validate_existing(columns)
    indexes = {
        str(index["name"]): index
        for index in sa.inspect(op.get_bind()).get_indexes("findings")
    }
    cvss_index = indexes.get("idx_findings_cvss")
    if cvss_index is not None:
        if cvss_index.get("column_names") != ["cvss_score"]:
            raise RuntimeError(_CATALOG_ERROR)
        op.drop_index("idx_findings_cvss", table_name="findings")
    if "trace_id" in columns:
        if dialect == "sqlite":
            with op.batch_alter_table("findings") as batch_op:
                batch_op.drop_column("trace_id")
        else:
            op.drop_column("findings", "trace_id")
