"""Harden finding trace metadata without taking ownership from revision 0002.

Revision ID: 0005
Revises: 0004
Create Date: 2025-01-05 00:00:00
"""
from __future__ import annotations

from typing import Protocol, cast

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None

_CATALOG_ERROR = "Incompatible findings catalog for migration 0005"


class _InvalidatableConnection(Protocol):
    def invalidate(self) -> None: ...


def _record_cleanup_failure(
    primary: Exception,
    action: str,
    cleanup_error: Exception,
) -> None:
    primary.add_note(
        "Migration 0005 savepoint cleanup failed "
        f"[{action}: {type(cleanup_error).__name__}]"
    )


def _invalidate_connection(bind: object, primary: Exception) -> None:
    try:
        cast(_InvalidatableConnection, bind).invalidate()
    except Exception as cleanup_error:
        _record_cleanup_failure(
            primary,
            "invalidate-connection",
            cleanup_error,
        )


def _catalog() -> tuple[str, dict[str, dict[str, object]]]:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError("Unsupported migration dialect")
    inspector = sa.inspect(bind)
    if "findings" not in inspector.get_table_names():
        raise RuntimeError(_CATALOG_ERROR)
    columns = {
        str(column["name"]): column
        for column in inspector.get_columns("findings")
    }
    trace = columns.get("trace_id")
    if trace is not None and not isinstance(
        trace["type"], (sa.Text, sa.String)
    ):
        raise RuntimeError(_CATALOG_ERROR)
    return dialect, columns


def _alter_trace(dialect: str, *, nullable: bool) -> None:
    if dialect == "sqlite":
        bind = op.get_bind()
        bind.exec_driver_sql("SAVEPOINT migration_0005_trace")
        try:
            with op.batch_alter_table("findings") as batch_op:
                batch_op.alter_column(
                    "trace_id",
                    existing_type=sa.Text(),
                    nullable=nullable,
                    server_default="",
                )
        except Exception as primary:
            primary_traceback = primary.__traceback__
            rollback_succeeded = False
            try:
                bind.exec_driver_sql(
                    "ROLLBACK TO SAVEPOINT migration_0005_trace"
                )
                rollback_succeeded = True
            except Exception as cleanup_error:
                _record_cleanup_failure(
                    primary,
                    "rollback-savepoint",
                    cleanup_error,
                )
                _invalidate_connection(bind, primary)
            if rollback_succeeded:
                try:
                    bind.exec_driver_sql(
                        "RELEASE SAVEPOINT migration_0005_trace"
                    )
                except Exception as cleanup_error:
                    _record_cleanup_failure(
                        primary,
                        "release-savepoint",
                        cleanup_error,
                    )
                    _invalidate_connection(bind, primary)
            raise primary.with_traceback(primary_traceback) from None
        else:
            bind.exec_driver_sql(
                "RELEASE SAVEPOINT migration_0005_trace"
            )
    else:
        op.alter_column(
            "findings",
            "trace_id",
            existing_type=sa.Text(),
            nullable=nullable,
            server_default="",
        )


def _trace_definition_matches(
    column: dict[str, object],
    *,
    nullable: bool,
) -> bool:
    default = column.get("default")
    normalized_default = (
        ""
        if default is None
        else str(default)
        .replace("(", "")
        .replace(")", "")
        .replace("::text", "")
        .strip()
        .strip("'")
    )
    return (
        bool(column.get("nullable", True)) is nullable
        and normalized_default == ""
        and default is not None
    )


def upgrade() -> None:
    dialect, columns = _catalog()
    if "trace_id" not in columns:
        column = sa.Column(
            "trace_id",
            sa.Text(),
            nullable=False,
            server_default="",
        )
        if dialect == "sqlite":
            with op.batch_alter_table("findings") as batch_op:
                batch_op.add_column(column)
        else:
            op.add_column("findings", column)
        return

    # Historical normalization policy:
    # - SQL NULL means no legacy trace identifier was recorded.
    # - It becomes the empty-string sentinel used for that same state.
    # - Existing empty and non-empty values remain exactly unchanged.
    # - No row is removed.
    # Ordering is deliberate: normalize, verify, then harden. Downgrade
    # relaxes nullability only because it cannot reconstruct which empty
    # values were formerly NULL.
    op.execute(
        sa.text("UPDATE findings SET trace_id='' WHERE trace_id IS NULL")
    )
    remaining_nulls = op.get_bind().execute(
        sa.text("SELECT count(*) FROM findings WHERE trace_id IS NULL")
    ).scalar_one()
    if remaining_nulls != 0:
        raise RuntimeError(_CATALOG_ERROR)
    if not _trace_definition_matches(
        columns["trace_id"],
        nullable=False,
    ):
        _alter_trace(dialect, nullable=False)


def downgrade() -> None:
    dialect, columns = _catalog()
    if "trace_id" not in columns:
        raise RuntimeError(_CATALOG_ERROR)
    if not bool(columns["trace_id"].get("nullable", True)):
        _alter_trace(dialect, nullable=True)
