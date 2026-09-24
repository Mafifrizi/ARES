"""
Reproduction test for NEW-02: Premature WebSocket Termination at T+15min
Verifies that a live WebSocket connection remains valid even after the short-lived
Bearer JWT access token's static expiry has passed, provided the underlying
refresh token family session remains active and unrevoked.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from ares.db.websocket_tickets import BearerTicketSource
from ares.db.database import AresDatabase


@pytest.mark.asyncio
async def test_websocket_stays_alive_past_bearer_access_token_expiry() -> None:
    """A live WebSocket connection must NOT be terminated simply because the 15-minute

    access token expired, as long as the user's session family is active.
    """
    db = AresDatabase(":memory:")
    await db.connect()

    try:
        user_id = await db.create_user("ws-test-operator", "Password123!", "operator")
        campaign_id = str(uuid4())
        from ares.core.campaign import Campaign
        campaign = Campaign(
            id=campaign_id,
            name="WebSocket Test Campaign",
            operator="ws-test-operator",
            targets=["127.0.0.1"],
        )
        await db.save_campaign(campaign)

        from ares.db.database import format_sqlite_utc
        from ares.core.token_sessions import generate_family_id
        now = datetime.now(timezone.utc)
        family_id = generate_family_id()
        created_str = format_sqlite_utc(now)
        abs_exp_str = format_sqlite_utc(now + timedelta(days=7))
        retain_str = format_sqlite_utc(now + timedelta(days=30))
        await db.conn.execute(
            """
            INSERT INTO refresh_token_families (
                id, user_id, auth_epoch, state, created_at, absolute_expires_at, retain_until
            ) VALUES (?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                family_id,
                user_id,
                1,
                created_str,
                abs_exp_str,
                retain_str,
            ),
        )
        await db.conn.commit()

        # Bearer token that expires in 15 minutes
        bearer_jti = str(uuid4())
        bearer_expiry = now + timedelta(minutes=15)
        source = BearerTicketSource(
            user_id=user_id,
            subject="ws-test-operator",
            jti=bearer_jti,
            expires_at=bearer_expiry,
            family_id=family_id,
            auth_epoch=1,
        )

        # Issue and consume ticket during initial connection
        raw_ticket, _ = await db.issue_websocket_ticket(campaign_id, source)
        assert raw_ticket is not None

        handle = await db.consume_websocket_ticket(raw_ticket, campaign_id)
        assert handle is not None

        # At T+0min, principal resolves successfully
        p0 = await db.resolve_websocket_ticket_principal(handle)
        assert p0 is not None
        assert p0.username == "ws-test-operator"
        assert p0.role == "operator"

        # Now simulate T+16min (bearer token expired, but session family still active)
        expired_bearer_handle = replace(
            handle,
            bearer_expires_at=now - timedelta(minutes=1),
        )

        # Under the bug (NEW-02), this returns None because of static bearer_expires_at check.
        # Under the fix, this must resolve successfully because the family session is active!
        p16 = await db.resolve_websocket_ticket_principal(expired_bearer_handle)
        assert p16 is not None, (
            "WebSocket principal resolution failed past bearer JWT expiry (NEW-02 regression). "
            "Live connections must remain valid while refresh token family is active."
        )
        assert p16.username == "ws-test-operator"

        # However, if the family session is revoked or absolutely expired, it MUST fail (fail-closed)
        revoked_ts = format_sqlite_utc(datetime.now(timezone.utc))
        await db.conn.execute(
            "UPDATE refresh_token_families SET state='revoked', revoked_at=?, revoke_reason='logout_current' WHERE id=?",
            (revoked_ts, family_id),
        )
        await db.conn.commit()
        p_revoked = await db.resolve_websocket_ticket_principal(expired_bearer_handle)
        # Test absolute expiration of family session
        # Reactivate family first
        await db.conn.execute(
            "UPDATE refresh_token_families SET state='active', revoked_at=NULL, revoke_reason=NULL, "
            "created_at='1999-01-01T00:00:00.000Z', absolute_expires_at='2000-01-01T00:00:00.000Z', "
            "retain_until='2000-01-02T00:00:00.000Z' WHERE id=?",
            (family_id,),
        )
        await db.conn.commit()
        p_expired = await db.resolve_websocket_ticket_principal(expired_bearer_handle)
        assert p_expired is None, "Expired token family must terminate WebSocket access"

    finally:
        await db.close()
