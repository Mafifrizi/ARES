"""
Reproduction test for ID-004: Campaign Lifecycle deletion fails on non-UUID slugs.
Verifies that campaigns created with slug-based or custom string identifiers
can be deleted cleanly without hitting INVALID_CONTRACT.
"""

import pytest

from ares.core.campaign import Campaign
from ares.db.database import AresDatabase
from ares.db.execution_lifecycle import FixedResult


@pytest.mark.asyncio
async def test_campaign_slug_deletion_lifecycle() -> None:
    db = AresDatabase(":memory:")
    await db.connect()

    try:
        slug_id = "test-camp-01"
        campaign = Campaign(
            id=slug_id,
            name="Test Slug Campaign",
            operator="admin",
            targets=["127.0.0.1"],
        )
        await db.save_campaign(campaign)

        # Verify saved
        found = await db.get_campaign(slug_id)
        assert found is not None
        assert found["id"] == slug_id

        # Delete campaign lifecycle
        result = await db.delete_campaign_lifecycle(slug_id)
        assert result.result is FixedResult.APPLIED, f"Expected APPLIED but got {result.result}"

        # Verify deleted
        after = await db.get_campaign(slug_id)
        assert after is None

        # Helper method delete_campaign returns True for fresh slug
        slug_id_2 = "test-camp-02"
        campaign_2 = Campaign(
            id=slug_id_2,
            name="Second Slug Campaign",
            operator="admin",
            targets=["127.0.0.1"],
        )
        await db.save_campaign(campaign_2)
        success = await db.delete_campaign(slug_id_2)
        assert success is True
        assert await db.get_campaign(slug_id_2) is None

        # Subsequent deletion returns False (already deleted)
        assert await db.delete_campaign(slug_id_2) is False

    finally:
        await db.close()
