"""Real PostgreSQL proof for authoritative refresh-token families."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from ares.core.token_sessions import (
    RefreshRotationStatus,
    SessionIssueStatus,
    SessionRevocationStatus,
)
from ares.db.postgres import PostgresDatabase
from tests.integration.test_postgres_auth_token_lifecycle import (
    _postgres_harness,
)


def _require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def _access_factory(_claims: object) -> str:
    return "fixed-access-result"


@pytest.mark.asyncio
async def test_real_postgres_replay_revokes_only_its_device_family() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        await database.create_user(
            "family-pg-user",
            "FamilyPostgres1!",
            "operator",
        )
        first = await database.create_login_session(
            "family-pg-user",
            "FamilyPostgres1!",
            _access_factory,
        )
        second = await database.create_login_session(
            "family-pg-user",
            "FamilyPostgres1!",
            _access_factory,
        )
        _require(
            first.status is SessionIssueStatus.ISSUED
            and first.session is not None
            and second.status is SessionIssueStatus.ISSUED
            and second.session is not None,
            "PostgreSQL login did not create device families",
        )
        first_raw = first.session.refresh_token
        first_family = first.session.family_id
        second_family = second.session.family_id
        rotated = await database.rotate_refresh_session(first_raw, _access_factory)
        replayed = await database.rotate_refresh_session(first_raw, _access_factory)
        first_authority = await database.resolve_access_token_principal(
            "family-pg-user",
            "fixed-first-jti",
            first_family,
            1,
        )
        second_authority = await database.resolve_access_token_principal(
            "family-pg-user",
            "fixed-second-jti",
            second_family,
            1,
        )
        _require(
            rotated.status is RefreshRotationStatus.ROTATED
            and replayed.status is RefreshRotationStatus.REPLAYED
            and first_authority is None
            and second_authority is not None,
            "PostgreSQL replay did not revoke exactly one device family",
        )


@pytest.mark.asyncio
async def test_real_postgres_two_pools_have_one_winner_then_family_revocation() -> None:
    async with _postgres_harness() as harness:
        primary = harness.database
        contender = PostgresDatabase(harness.dsn, pool_min=1, pool_max=2)
        await contender.connect()
        try:
            await primary.create_user(
                "family-race-user",
                "FamilyRacePass1!",
                "reporter",
            )
            issued = await primary.create_login_session(
                "family-race-user",
                "FamilyRacePass1!",
                _access_factory,
            )
            _require(
                issued.session is not None,
                "PostgreSQL race fixture did not issue a session",
            )
            raw_token = issued.session.refresh_token
            family_id = issued.session.family_id
            first, second = await asyncio.gather(
                primary.rotate_refresh_session(raw_token, _access_factory),
                contender.rotate_refresh_session(raw_token, _access_factory),
            )
            statuses = {first.status, second.status}
            authority = await contender.resolve_access_token_principal(
                "family-race-user",
                "fixed-race-jti",
                family_id,
                1,
            )
            _require(
                statuses
                == {
                    RefreshRotationStatus.ROTATED,
                    RefreshRotationStatus.REPLAYED,
                }
                and authority is None,
                "PostgreSQL concurrent loser did not revoke the winning family",
            )
        finally:
            await contender.close()


@pytest.mark.asyncio
async def test_real_postgres_logout_all_advances_epoch_across_pools() -> None:
    async with _postgres_harness() as harness:
        primary = harness.database
        observer = PostgresDatabase(harness.dsn, pool_min=1, pool_max=2)
        await observer.connect()
        try:
            user_id = await primary.create_user(
                "family-epoch-user",
                "FamilyEpochPass1!",
                "recon",
            )
            issued = await primary.create_login_session(
                "family-epoch-user",
                "FamilyEpochPass1!",
                _access_factory,
            )
            _require(
                issued.session is not None,
                "PostgreSQL epoch fixture did not issue a session",
            )
            revoked = await primary.revoke_all_sessions(
                user_id=user_id,
                jti="fixed-epoch-jti",
                expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            )
            authority = await observer.resolve_access_token_principal(
                "family-epoch-user",
                "fixed-observer-jti",
                issued.session.family_id,
                issued.session.auth_epoch,
            )
            _require(
                revoked.status is SessionRevocationStatus.REVOKED
                and authority is None,
                "PostgreSQL logout-all was not immediately authoritative",
            )
        finally:
            await observer.close()
