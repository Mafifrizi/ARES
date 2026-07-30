"""Rename credential cracked-value storage without guessing catalog state.

Revision ID: 0006
Revises: 0005
Create Date: 2026-03-22 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None

_CATALOG_ERROR = "Incompatible credentials catalog for migration 0006"
_AMBIGUOUS_ERROR = "Ambiguous credentials catalog for migration 0006"


def _catalog() -> tuple[
    str,
    dict[str, dict[str, object]],
    dict[str, tuple[str, object]],
]:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError("Unsupported migration dialect")
    inspector = sa.inspect(bind)
    if "credentials" not in inspector.get_table_names():
        raise RuntimeError(_CATALOG_ERROR)
    columns = {
        str(column["name"]): column
        for column in inspector.get_columns("credentials")
    }
    declared: dict[str, tuple[str, object]] = {}
    if dialect == "sqlite":
        rows = bind.exec_driver_sql(
            'PRAGMA table_info("credentials")'
        ).fetchall()
        declared = {
            str(row[1]): (str(row[2]), row[4])
            for row in rows
        }
    else:
        rows = bind.execute(
            sa.text(
                """
                SELECT
                    attribute.attname AS column_name,
                    format_type(
                        attribute.atttypid,
                        attribute.atttypmod
                    ) AS declared_type,
                    definition.oid IS NOT NULL AS has_default
                FROM pg_attribute AS attribute
                JOIN pg_class AS relation
                  ON relation.oid=attribute.attrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                LEFT JOIN pg_attrdef AS definition
                  ON definition.adrelid=attribute.attrelid
                 AND definition.adnum=attribute.attnum
                WHERE namespace.nspname=current_schema()
                  AND relation.relname='credentials'
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
                """
            )
        ).mappings()
        declared = {
            str(row["column_name"]): (
                str(row["declared_type"]),
                bool(row["has_default"]),
            )
            for row in rows
        }
    return dialect, columns, declared


def _validate_column(
    dialect: str,
    name: str,
    columns: dict[str, dict[str, object]],
    declared: dict[str, tuple[str, object]],
) -> None:
    column = columns[name]
    column_type = column["type"]
    if (
        not isinstance(column_type, sa.Text)
        or type(column_type).__name__ != "TEXT"
        or column.get("nullable") is not True
        or column.get("default") is not None
    ):
        raise RuntimeError(_CATALOG_ERROR)
    if dialect == "sqlite":
        declared_type, declared_default = declared.get(name, ("", object()))
        if declared_type != "TEXT" or declared_default is not None:
            raise RuntimeError(_CATALOG_ERROR)
    else:
        declared_type, has_default = declared.get(name, ("", object()))
        if declared_type != "text" or has_default is not False:
            raise RuntimeError(_CATALOG_ERROR)


def _rename(source: str, target: str) -> None:
    dialect, columns, declared = _catalog()
    source_exists = source in columns
    target_exists = target in columns
    if source_exists and target_exists:
        raise RuntimeError(_AMBIGUOUS_ERROR)
    if not source_exists and not target_exists:
        raise RuntimeError(_CATALOG_ERROR)
    existing_name = target if target_exists else source
    _validate_column(dialect, existing_name, columns, declared)
    if target_exists:
        return

    op.alter_column(
        "credentials",
        source,
        new_column_name=target,
        existing_type=sa.Text(),
        existing_nullable=True,
    )

    after_dialect, after, after_declared = _catalog()
    if source in after or target not in after:
        raise RuntimeError(_CATALOG_ERROR)
    _validate_column(after_dialect, target, after, after_declared)


def upgrade() -> None:
    _rename("cracked_value", "cracked_value_enc")


def downgrade() -> None:
    _rename("cracked_value_enc", "cracked_value")
