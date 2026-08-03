"""Deterministic SQLite and contract coverage for refresh-token families."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ares.core.security import create_access_token, decode_access_token
from ares.core.token_sessions import (
    RefreshRotationStatus,
    SessionIssueStatus,
    SessionRevocationStatus,
    generate_family_id,
    generate_refresh_token,
    hash_refresh_token,
    is_canonical_family_id,
    is_canonical_refresh_hash,
)
from ares.db.database import AresDatabase


def _require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def _access_factory(_claims: object) -> str:
    return "fixed-access-result"


def test_family_and_refresh_contracts_are_canonical_and_confidential() -> None:
    family_id = generate_family_id()
    raw_token = generate_refresh_token()
    token_hash = hash_refresh_token(raw_token)
    invalid_family_values = (
        family_id + "=",
        " " + family_id,
        family_id + " ",
        family_id[:-1],
        family_id + "A",
    )
    canonical = (
        len(family_id) == 43
        and is_canonical_family_id(family_id)
        and all(not is_canonical_family_id(value) for value in invalid_family_values)
        and len(token_hash) == 64
        and is_canonical_refresh_hash(token_hash)
        and not is_canonical_refresh_hash(token_hash.upper())
        and raw_token not in repr(token_hash)
    )
    _require(canonical, "token-family canonical contract changed")


def test_family_access_token_has_required_claims_and_no_role() -> None:
    family_id = generate_family_id()
    token = create_access_token(
        {"sub": "fixed-subject", "sid": family_id, "ver": 7, "role": "admin"},
        "fixed-test-secret-that-is-long-enough",
    )
    decoded = decode_access_token(
        token,
        "fixed-test-secret-that-is-long-enough",
    )
    claims_are_canonical = (
        isinstance(decoded, dict)
        and set(decoded) == {"sub", "sid", "ver", "exp", "iat", "jti"}
        and decoded.get("sid") == family_id
        and decoded.get("ver") == 7
        and "role" not in decoded
    )
    _require(claims_are_canonical, "family access-token claims changed")

    for claims in (
        {"sub": "fixed-subject", "sid": family_id},
        {"sub": "fixed-subject", "ver": 1},
        {"sub": "fixed-subject", "sid": family_id + "=", "ver": 1},
        {"sub": "fixed-subject", "sid": family_id, "ver": True},
    ):
        with pytest.raises(ValueError, match="invalid access token claims"):
            create_access_token(claims, "fixed-test-secret-that-is-long-enough")


@pytest.mark.asyncio
async def test_sqlite_replay_revokes_only_the_replayed_device_family(
    tmp_path,
) -> None:
    database = AresDatabase(str(tmp_path / "family-isolation.db"))
    await database.connect()
    try:
        await database.create_user(
            "family-user",
            "FamilyPassword1!",
            "operator",
        )
        first = await database.create_login_session(
            "family-user",
            "FamilyPassword1!",
            _access_factory,
        )
        second = await database.create_login_session(
            "family-user",
            "FamilyPassword1!",
            _access_factory,
        )
        _require(
            first.status is SessionIssueStatus.ISSUED
            and first.session is not None
            and second.status is SessionIssueStatus.ISSUED
            and second.session is not None
            and first.session.family_id != second.session.family_id,
            "login did not create isolated device families",
        )
        first_raw = first.session.refresh_token
        first_family = first.session.family_id
        second_family = second.session.family_id
        rotated = await database.rotate_refresh_session(first_raw, _access_factory)
        replayed = await database.rotate_refresh_session(first_raw, _access_factory)
        first_authority = await database.resolve_access_token_principal(
            "family-user",
            "fixed-first-jti",
            first_family,
            1,
        )
        second_authority = await database.resolve_access_token_principal(
            "family-user",
            "fixed-second-jti",
            second_family,
            1,
        )
        safe_result = (
            rotated.status is RefreshRotationStatus.ROTATED
            and rotated.session is not None
            and replayed.status is RefreshRotationStatus.REPLAYED
            and first_authority is None
            and second_authority is not None
        )
        _require(safe_result, "known replay did not isolate and revoke its family")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_logout_all_increments_epoch_and_is_read_only_afterward(
    tmp_path,
) -> None:
    database = AresDatabase(str(tmp_path / "logout-all.db"))
    await database.connect()
    try:
        user_id = await database.create_user(
            "epoch-user",
            "EpochPassword1!",
            "reporter",
        )
        issued = await database.create_login_session(
            "epoch-user",
            "EpochPassword1!",
            _access_factory,
        )
        _require(
            issued.session is not None,
            "login did not create a family before logout-all",
        )
        family_id = issued.session.family_id
        expires_at = datetime(2099, 1, 1, tzinfo=timezone.utc)
        revoked = await database.revoke_all_sessions(
            user_id=user_id,
            jti="fixed-logout-jti",
            expires_at=expires_at,
        )
        principal = await database.resolve_access_token_principal(
            "epoch-user",
            "fixed-read-jti",
            family_id,
            1,
        )
        async with database.conn.execute(
            "SELECT auth_epoch FROM users WHERE id=?",
            (user_id,),
        ) as cursor:
            row = await cursor.fetchone()
        _require(
            revoked.status is SessionRevocationStatus.REVOKED
            and principal is None
            and row is not None
            and int(row["auth_epoch"]) == 2,
            "logout-all did not advance authoritative epoch",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_issued_session_exposes_authoritative_absolute_expiry(tmp_path) -> None:
    database = AresDatabase(str(tmp_path / "cookie-expiry.db"))
    await database.connect()
    try:
        await database.create_user("cookie-user", "CookiePassword1!", "operator")
        issued = await database.create_login_session(
            "cookie-user", "CookiePassword1!", _access_factory
        )
        now = datetime.now(timezone.utc)
        _require(
            issued.session is not None
            and issued.session.absolute_expires_at.tzinfo is not None
            and issued.session.absolute_expires_at > now,
            "issued session did not expose authoritative family expiry",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_cookie_logout_revokes_active_family_and_is_idempotent(tmp_path) -> None:
    database = AresDatabase(str(tmp_path / "cookie-logout.db"))
    await database.connect()
    try:
        await database.create_user("logout-user", "LogoutPassword1!", "operator")
        issued = await database.create_login_session(
            "logout-user", "LogoutPassword1!", _access_factory
        )
        _require(issued.session is not None, "login session missing")
        raw = issued.session.refresh_token
        revoked = await database.revoke_refresh_cookie_session(raw)
        repeated = await database.revoke_refresh_cookie_session(raw)
        rotation = await database.rotate_refresh_session(raw, _access_factory)
        _require(
            revoked.status is SessionRevocationStatus.REVOKED
            and repeated.status is SessionRevocationStatus.ALREADY_REVOKED
            and rotation.status is not RefreshRotationStatus.ROTATED,
            "cookie logout did not revoke exactly one family",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_consumed_cookie_logout_triggers_replay_revocation(tmp_path) -> None:
    database = AresDatabase(str(tmp_path / "cookie-replay.db"))
    await database.connect()
    try:
        await database.create_user("replay-user", "ReplayPassword1!", "operator")
        issued = await database.create_login_session(
            "replay-user", "ReplayPassword1!", _access_factory
        )
        _require(issued.session is not None, "login session missing")
        predecessor = issued.session.refresh_token
        rotated = await database.rotate_refresh_session(predecessor, _access_factory)
        _require(rotated.session is not None, "rotation successor missing")
        replay_logout = await database.revoke_refresh_cookie_session(predecessor)
        successor = await database.rotate_refresh_session(
            rotated.session.refresh_token, _access_factory
        )
        unknown = await database.revoke_refresh_cookie_session("u" * 64)
        _require(
            replay_logout.status is SessionRevocationStatus.REVOKED
            and successor.status is not RefreshRotationStatus.ROTATED
            and unknown.status is SessionRevocationStatus.INVALID,
            "consumed-cookie logout did not preserve replay authority",
        )
    finally:
        await database.close()
