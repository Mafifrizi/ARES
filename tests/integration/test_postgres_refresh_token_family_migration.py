"""Real PostgreSQL migration and catalog proof for revision 0009."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.integration import test_postgres_migration_portability as harness


def _require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


async def _seed_revision_0008(
    connection: object,
    *,
    legacy_identifier: str,
) -> None:
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role) "
        "VALUES($1,$2,$3,$4)",
        "family-migration-user",
        "family-migration-user",
        "fixed-hash",
        "operator",
    )
    await connection.execute(
        "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES($1,$2,$3)",
        legacy_identifier,
        "family-migration-user",
        datetime(2099, 1, 1, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_real_postgres_revision_0009_preserves_and_resets_sessions() -> None:
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            await _seed_revision_0008(connection, legacy_identifier="a" * 64)
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0009")
        connection = await harness._connect(target)
        try:
            state = await connection.fetchrow(
                """
                SELECT
                    (SELECT version_num='0009' FROM alembic_version)
                        AS revision_current,
                    (SELECT auth_epoch=1 FROM users
                     WHERE id='family-migration-user') AS epoch_current,
                    (SELECT state='retired' AND is_revoked=1
                     FROM refresh_tokens) AS legacy_retired,
                    (SELECT count(*)=1 AND bool_and(
                        state='revoked' AND revoke_reason='rollout_reset'
                     ) FROM refresh_token_families) AS family_reset,
                    EXISTS(
                        SELECT 1 FROM pg_constraint
                        WHERE conname='fk_refresh_token_family_owner'
                          AND convalidated AND NOT condeferrable
                    ) AS owner_fk,
                    EXISTS(
                        SELECT 1 FROM pg_indexes
                        WHERE indexname='uq_refresh_token_one_active'
                          AND indexdef LIKE '%WHERE (state = ''active''::text)%'
                    ) AS active_index
                """
            )
            canonical = state is not None and all(bool(value) for value in state.values())
        finally:
            await connection.close()
    _require(canonical, "PostgreSQL revision 0009 catalog or reset was incomplete")


@pytest.mark.asyncio
async def test_real_postgres_revision_0009_rejects_unsafe_legacy_hash_atomically(
) -> None:
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            await _seed_revision_0008(
                connection,
                legacy_identifier="not-a-hash",
            )
        finally:
            await connection.close()
        rejected = False
        try:
            await harness._alembic(target, "upgrade", "0009")
        except RuntimeError:
            rejected = True
        connection = await harness._connect(target)
        try:
            state = await connection.fetchrow(
                """
                SELECT
                    (SELECT version_num='0008' FROM alembic_version)
                        AS revision_unchanged,
                    to_regclass('refresh_token_families') IS NULL
                        AS no_family_table,
                    NOT EXISTS(
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema=current_schema()
                          AND table_name='users'
                          AND column_name='auth_epoch'
                    ) AS no_epoch_column,
                    (SELECT count(*)=1 FROM refresh_tokens
                     WHERE id='not-a-hash') AS row_unchanged
                """
            )
            unchanged = (
                rejected
                and state is not None
                and all(bool(value) for value in state.values())
                and await connection.fetchval("SELECT 1") == 1
            )
        finally:
            await connection.close()
    _require(unchanged, "unsafe PostgreSQL legacy data was partially migrated")


@pytest.mark.asyncio
async def test_real_postgres_family_finite_and_single_active_constraints() -> None:
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0009")
        connection = await harness._connect(target)
        try:
            await connection.execute(
                "INSERT INTO users(id,username,hashed_password,role) "
                "VALUES($1,$2,$3,$4)",
                "family-constraint-user",
                "family-constraint-user",
                "fixed-hash",
                "reporter",
            )
            finite_rejected = await harness._postgres_integrity_failure(
                connection,
                "INSERT INTO refresh_token_families("
                "id,user_id,auth_epoch,state,created_at,absolute_expires_at,"
                "retain_until) VALUES("
                "$1,$2,1,'active',$3,'infinity'::timestamptz,$4)",
                "A" * 43,
                "family-constraint-user",
                datetime(2030, 1, 1, tzinfo=timezone.utc),
                datetime(2030, 3, 1, tzinfo=timezone.utc),
                expected_type="CheckViolationError",
            )
            await connection.execute(
                "INSERT INTO refresh_token_families("
                "id,user_id,auth_epoch,state,created_at,absolute_expires_at,"
                "retain_until) VALUES($1,$2,1,'active',$3,$4,$5)",
                "A" * 43,
                "family-constraint-user",
                datetime(2030, 1, 1, tzinfo=timezone.utc),
                datetime(2030, 2, 1, tzinfo=timezone.utc),
                datetime(2030, 3, 1, tzinfo=timezone.utc),
            )
            await connection.execute(
                "INSERT INTO refresh_tokens("
                "id,user_id,is_revoked,expires_at,created_at,family_id,parent_id,"
                "generation,state,used_at) VALUES($1,$2,1,$3,$4,$5,NULL,0,"
                "'consumed',$4)",
                "b" * 64,
                "family-constraint-user",
                datetime(2030, 2, 1, tzinfo=timezone.utc),
                datetime(2030, 1, 1, tzinfo=timezone.utc),
                "A" * 43,
            )
            await connection.execute(
                "INSERT INTO refresh_tokens("
                "id,user_id,is_revoked,expires_at,created_at,family_id,parent_id,"
                "generation,state) VALUES($1,$2,0,$3,$4,$5,$6,1,'active')",
                "c" * 64,
                "family-constraint-user",
                datetime(2030, 2, 1, tzinfo=timezone.utc),
                datetime(2030, 1, 2, tzinfo=timezone.utc),
                "A" * 43,
                "b" * 64,
            )
            active_rejected = await harness._postgres_integrity_failure(
                connection,
                "INSERT INTO refresh_tokens("
                "id,user_id,is_revoked,expires_at,created_at,family_id,parent_id,"
                "generation,state) VALUES($1,$2,0,$3,$4,$5,$6,2,'active')",
                "d" * 64,
                "family-constraint-user",
                datetime(2030, 2, 1, tzinfo=timezone.utc),
                datetime(2030, 1, 3, tzinfo=timezone.utc),
                "A" * 43,
                "c" * 64,
                expected_type="UniqueViolationError",
            )
        finally:
            await connection.close()
    _require(
        finite_rejected,
        "PostgreSQL finite family constraint was not enforced",
    )
    _require(
        active_rejected,
        "PostgreSQL single-active family constraint was not enforced",
    )
