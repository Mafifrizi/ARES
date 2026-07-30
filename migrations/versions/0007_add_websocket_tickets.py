"""Add one-time WebSocket ticket storage.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-28 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None


def _timestamp_type(dialect: str) -> sa.types.TypeEngine:
    if dialect == "postgresql":
        return sa.DateTime(timezone=True)
    if dialect == "sqlite":
        return sa.Text()
    raise RuntimeError("Unsupported WebSocket ticket migration dialect")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    timestamp_type = _timestamp_type(dialect)
    is_postgresql = dialect == "postgresql"
    hash_check = (
        "ticket_hash ~ '^[0-9a-f]{64}$'"
        if is_postgresql
        else (
            "length(ticket_hash)=64 "
            "AND ticket_hash NOT GLOB '*[^0-9a-f]*'"
        )
    )
    created_check = (
        "created_at < expires_at"
        if is_postgresql
        else (
            "strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at)=created_at"
        )
    )
    expires_check = (
        "expires_at > created_at"
        if is_postgresql
        else (
            "strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at)=expires_at"
        )
    )
    consumed_check = (
        "consumed_at IS NULL OR consumed_at < expires_at"
        if is_postgresql
        else (
            "consumed_at IS NULL OR ("
            "strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at)=consumed_at)"
        )
    )
    bearer_timestamp_check = (
        ""
        if is_postgresql
        else (
            "AND "
            "strftime("
            "'%Y-%m-%dT%H:%M:%fZ', bearer_expires_at"
            ") IS NOT NULL "
            "AND strftime("
            "'%Y-%m-%dT%H:%M:%fZ', bearer_expires_at"
            ")=bearer_expires_at"
        )
    )
    time_order_check = (
        "expires_at > created_at "
        "AND (consumed_at IS NULL OR consumed_at < expires_at)"
        if is_postgresql
        else (
            "julianday(expires_at) > julianday(created_at) "
            "AND (consumed_at IS NULL "
            "OR julianday(consumed_at) < julianday(expires_at))"
        )
    )
    trim_function = "btrim" if is_postgresql else "trim"
    source_shape = f"""
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length({trim_function}(bearer_subject)) > 0
            AND bearer_subject={trim_function}(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length({trim_function}(bearer_jti)) > 0
            AND bearer_jti={trim_function}(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            {bearer_timestamp_check}
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND api_key_id IS NOT NULL
            AND length({trim_function}(api_key_id)) > 0
            AND api_key_id={trim_function}(api_key_id)
            AND required_scope='read'
        )
    """
    finite_constraints = (
        (
            sa.CheckConstraint(
                "bearer_expires_at IS NULL "
                "OR isfinite(bearer_expires_at)",
                name="ck_ws_ticket_bearer_expires_finite",
            ),
            sa.CheckConstraint(
                "isfinite(created_at)",
                name="ck_ws_ticket_created_finite",
            ),
            sa.CheckConstraint(
                "isfinite(expires_at)",
                name="ck_ws_ticket_expires_finite",
            ),
            sa.CheckConstraint(
                "consumed_at IS NULL OR isfinite(consumed_at)",
                name="ck_ws_ticket_consumed_finite",
            ),
        )
        if is_postgresql
        else ()
    )

    op.create_table(
        "websocket_tickets",
        sa.Column(
            "ticket_hash", sa.Text(), primary_key=True, nullable=False
        ),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_ws_ticket_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey(
                "users.id",
                name="fk_ws_ticket_user",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("credential_kind", sa.Text(), nullable=False),
        sa.Column("bearer_subject", sa.Text()),
        sa.Column("bearer_jti", sa.Text()),
        sa.Column("bearer_expires_at", timestamp_type),
        sa.Column(
            "api_key_id",
            sa.Text(),
            sa.ForeignKey(
                "api_keys.id",
                name="fk_ws_ticket_api_key",
                ondelete="CASCADE",
            ),
        ),
        sa.Column("required_scope", sa.Text()),
        sa.Column("created_at", timestamp_type, nullable=False),
        sa.Column("expires_at", timestamp_type, nullable=False),
        sa.Column("consumed_at", timestamp_type),
        sa.CheckConstraint(hash_check, name="ck_ws_ticket_hash"),
        sa.CheckConstraint(
            "credential_kind IN ('bearer', 'api_key')",
            name="ck_ws_ticket_kind",
        ),
        sa.CheckConstraint(created_check, name="ck_ws_ticket_created_at"),
        sa.CheckConstraint(expires_check, name="ck_ws_ticket_expires_at"),
        sa.CheckConstraint(consumed_check, name="ck_ws_ticket_consumed_at"),
        sa.CheckConstraint(
            time_order_check,
            name="ck_ws_ticket_time_order",
        ),
        sa.CheckConstraint(source_shape, name="ck_ws_ticket_source_shape"),
        *finite_constraints,
    )
    op.create_index(
        "idx_ws_tickets_expires", "websocket_tickets", ["expires_at"]
    )
    op.create_index(
        "idx_ws_tickets_user", "websocket_tickets", ["user_id"]
    )
    op.create_index(
        "idx_ws_tickets_campaign", "websocket_tickets", ["campaign_id"]
    )
    op.create_index(
        "idx_ws_tickets_api_key", "websocket_tickets", ["api_key_id"]
    )


def downgrade() -> None:
    op.drop_index("idx_ws_tickets_api_key", table_name="websocket_tickets")
    op.drop_index("idx_ws_tickets_campaign", table_name="websocket_tickets")
    op.drop_index("idx_ws_tickets_user", table_name="websocket_tickets")
    op.drop_index("idx_ws_tickets_expires", table_name="websocket_tickets")
    op.drop_table("websocket_tickets")
