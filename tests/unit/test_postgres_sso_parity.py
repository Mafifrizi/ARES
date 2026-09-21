"""Unit tests for PostgreSQL Enterprise SSO interface and schema parity."""
from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.db.database import AresDatabase
from ares.db.postgres import (
    _POSTGRES_MANAGED_REVISION,
    _POSTGRES_MANAGED_TABLES,
    _POSTGRES_OLDER_REVISIONS,
    PostgresDatabase,
)


def test_sso_method_interface_parity():
    """Verify that PostgresDatabase implements all SSO methods from AresDatabase."""
    sso_methods = [
        "get_organization",
        "get_sso_config",
        "save_sso_config",
        "create_sso_flow_state",
        "consume_sso_flow_state",
        "provision_or_get_sso_user",
        "create_sso_session",
    ]

    for method_name in sso_methods:
        assert hasattr(AresDatabase, method_name), f"AresDatabase missing {method_name}"
        assert hasattr(PostgresDatabase, method_name), f"PostgresDatabase missing {method_name}"

        ares_sig = inspect.signature(getattr(AresDatabase, method_name))
        pg_sig = inspect.signature(getattr(PostgresDatabase, method_name))

        # Ensure parameters match
        ares_params = list(ares_sig.parameters.keys())
        pg_params = list(pg_sig.parameters.keys())
        assert ares_params == pg_params, (
            f"Parameter mismatch on {method_name}: {ares_params} vs {pg_params}"
        )


def test_postgres_baseline_schema_invariants():
    """Verify that Postgres schema invariant constants preserve baseline revision 0011 contract."""
    # 1. Revision progression frozen at 0011
    assert _POSTGRES_MANAGED_REVISION == "0011"
    assert "0010" in _POSTGRES_OLDER_REVISIONS

    # 2. Managed tables: 14 baseline tables
    assert len(_POSTGRES_MANAGED_TABLES) == 14
    assert "campaigns" in _POSTGRES_MANAGED_TABLES
    assert "users" in _POSTGRES_MANAGED_TABLES
    assert "websocket_tickets" in _POSTGRES_MANAGED_TABLES


@pytest.mark.asyncio
async def test_postgres_ensure_sso_schema_ddl():
    """Verify that _ensure_sso_schema executes DDL for enterprise SSO tables and columns."""
    mock_conn = AsyncMock()
    await PostgresDatabase._ensure_sso_schema(mock_conn)

    assert mock_conn.execute.called
    ddl_call_args = mock_conn.execute.call_args[0][0]
    assert "CREATE TABLE IF NOT EXISTS organizations" in ddl_call_args
    assert "CREATE TABLE IF NOT EXISTS sso_configurations" in ddl_call_args
    assert "CREATE TABLE IF NOT EXISTS sso_flow_states" in ddl_call_args
    assert "ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id" in ddl_call_args
    assert "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider" in ddl_call_args
    assert "ALTER TABLE users ADD COLUMN IF NOT EXISTS external_subject_id" in ddl_call_args
    assert "INSERT INTO organizations" in ddl_call_args


@pytest.mark.asyncio
async def test_postgres_database_sso_mocked_flow():
    """Verify PostgresDatabase SSO queries using mocked asyncpg pool."""
    db = PostgresDatabase("postgresql://ares:secret@localhost:5432/ares_db")
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    # Context manager setup for acquire()
    acquire_ctx = AsyncMock()
    acquire_ctx.__aenter__.return_value = mock_conn
    acquire_ctx.__aexit__.return_value = None
    mock_pool.acquire.return_value = acquire_ctx

    # Context manager setup for conn.transaction()
    tx_ctx = AsyncMock()
    tx_ctx.__aenter__.return_value = None
    tx_ctx.__aexit__.return_value = None
    mock_conn.transaction = MagicMock(return_value=tx_ctx)

    db._pool = mock_pool

    # 1. Test get_organization
    mock_conn.fetchrow.return_value = {
        "id": "org-123",
        "slug": "enterprise",
        "name": "Enterprise Corp",
        "is_active": 1,
    }
    org = await db.get_organization("enterprise")
    assert org is not None
    assert org["id"] == "org-123"
    mock_conn.fetchrow.assert_called_with(
        "SELECT * FROM organizations WHERE slug=$1 OR id=$1",
        "enterprise",
    )

    # 2. Test get_sso_config
    mock_conn.fetchrow.return_value = {
        "id": "cfg-123",
        "org_id": "org-123",
        "protocol": "saml",
        "is_enabled": 1,
        "sso_url": "https://idp.example.com/sso",
    }
    cfg = await db.get_sso_config("org-123", protocol="saml")
    assert cfg is not None
    assert cfg["protocol"] == "saml"

    # 3. Test save_sso_config
    sso_id = await db.save_sso_config(
        org_id="org-123",
        protocol="oidc",
        client_id="ares-app",
        sso_url="https://idp.example.com/auth",
    )
    assert len(sso_id) == 36  # UUIDv4 format
    assert mock_conn.execute.called

    # 4. Test create_sso_flow_state
    state_id = await db.create_sso_flow_state(
        org_id="org-123",
        flow_type="saml",
        flow_id="req-123",
        ttl_minutes=10,
    )
    assert len(state_id) == 36
    assert mock_conn.execute.called

    # 5. Test consume_sso_flow_state (atomic transaction)
    mock_conn.fetchrow.return_value = {
        "id": "state-uuid",
        "org_id": "org-123",
        "flow_type": "saml",
        "flow_id": "req-123",
        "is_consumed": 0,
    }
    consumed = await db.consume_sso_flow_state("req-123", "saml")
    assert consumed is not None
    assert consumed["id"] == "state-uuid"
    assert mock_conn.transaction.called

    # 6. Test provision_or_get_sso_user
    mock_conn.fetchrow.return_value = {
        "id": "user-uuid",
        "username": "sso_operator@corp.local",
        "role": "operator",
        "is_active": 1,
    }
    user = await db.provision_or_get_sso_user(
        org_id="org-123",
        username="sso_operator@corp.local",
        role="operator",
        auth_provider="saml",
    )
    assert user is not None
    assert user["username"] == "sso_operator@corp.local"
