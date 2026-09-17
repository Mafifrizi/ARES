from pathlib import Path
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.db.database import AresDatabase


@pytest.fixture
def settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="test-secret-key-min32-chars-xxxxxx",
        ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
    )


@pytest.fixture
def campaign() -> Campaign:
    return Campaign(
        name="Status Transition Test",
        client="Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
        operator="tester",
    )


@pytest.fixture
async def db(settings: AresSettings, tmp_path: Path) -> AresDatabase:
    db_path = tmp_path / "test_ares.db"
    database = AresDatabase(str(db_path), settings.encryption_key_value)
    await database.connect()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_update_campaign_status_direct(db: AresDatabase, campaign: Campaign) -> None:
    await db.save_campaign(campaign)
    c_row = await db.get_campaign(campaign.id)
    assert c_row is not None
    assert c_row["status"] == "created"

    success = await db.update_campaign_status(campaign.id, "running")
    assert success is True

    c_row2 = await db.get_campaign(campaign.id)
    assert c_row2 is not None
    assert c_row2["status"] == "running"


@pytest.mark.asyncio
async def test_record_module_run_auto_transitions_created_to_running(
    db: AresDatabase, campaign: Campaign
) -> None:
    await db.save_campaign(campaign)
    c_row = await db.get_campaign(campaign.id)
    assert c_row is not None
    assert c_row["status"] == "created"

    await db.record_module_run(
        campaign_id=campaign.id,
        module_id="network.port_scan",
        outcome="success",
        success=True,
        duration_ms=45.0,
    )

    c_row2 = await db.get_campaign(campaign.id)
    assert c_row2 is not None
    assert c_row2["status"] == "running"


@pytest.mark.asyncio
async def test_record_module_run_does_not_override_completed_status(
    db: AresDatabase, campaign: Campaign
) -> None:
    await db.save_campaign(campaign)
    await db.update_campaign_status(campaign.id, "completed")

    c_row = await db.get_campaign(campaign.id)
    assert c_row is not None
    assert c_row["status"] == "completed"

    await db.record_module_run(
        campaign_id=campaign.id,
        module_id="network.port_scan",
        outcome="success",
        success=True,
        duration_ms=10.0,
    )

    c_row2 = await db.get_campaign(campaign.id)
    assert c_row2 is not None
    assert c_row2["status"] == "completed"


@pytest.mark.asyncio
async def test_server_record_module_run_transitions_created_to_running(
    db: AresDatabase, campaign: Campaign
) -> None:
    from ares.api.server import _record_module_run

    await db.save_campaign(campaign)
    c_row = await db.get_campaign(campaign.id)
    assert c_row is not None
    assert c_row["status"] == "created"

    await _record_module_run(
        db=db,
        campaign_id=campaign.id,
        module_id="network.port_scan",
        outcome="success",
        success=True,
        duration_ms=50.0,
    )

    c_row2 = await db.get_campaign(campaign.id)
    assert c_row2 is not None
    assert c_row2["status"] == "running"

