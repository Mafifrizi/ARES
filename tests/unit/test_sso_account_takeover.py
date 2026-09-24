import pytest
from ares.db.database import AresDatabase


@pytest.mark.asyncio
async def test_sso_cannot_takeover_local_account(tmp_path):
    """
    NEW-01 Reproduction:
    Verify that an SSO JIT login with a colliding username CANNOT
    link itself to, overwrite, or take over a pre-existing local user account.
    """
    db_file = tmp_path / "test_sso_takeover.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    try:
        # 1. Existing local administrator account
        local_admin_id = await db.create_user(
            username="admin",
            password="OriginalLocalPassword123!",
            role="team_lead",
            created_by="system",
        )
        local_user_before = await db.get_user("admin")
        assert local_user_before is not None
        assert local_user_before["id"] == local_admin_id
        assert local_user_before["auth_provider"] == "local"
        assert local_user_before["external_subject_id"] is None

        # 2. Malicious / colliding SSO login from external IdP with username "admin"
        # The system must reject the hijacking by raising ValueError or refusing to link.
        with pytest.raises(ValueError, match="collides with an existing local account|already registered"):
            await db.provision_or_get_sso_user(
                org_id="org-external",
                username="admin",
                role="reporter",
                external_id="attacker-idp-subject-999",
                auth_provider="oidc",
            )

        # 3. Verify local admin was NOT modified or bound to attacker's external ID
        local_user_after = await db.get_user("admin")
        assert local_user_after["id"] == local_admin_id
        assert local_user_after["role"] == "team_lead"
        assert local_user_after["auth_provider"] == "local"
        assert local_user_after["external_subject_id"] is None

    finally:
        await db.close()
