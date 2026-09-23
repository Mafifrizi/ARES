import pytest
from unittest.mock import AsyncMock, patch

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.modules.credential.ssh_spray import SSHSprayModule
from ares.modules.params import SSHSprayParams
from ares.sdk import OpsecLevel


def _make_module() -> tuple[SSHSprayModule, Campaign]:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="SSH-Spray-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = SSHSprayModule(settings=settings, campaign=campaign, noise=noise)
    return mod, campaign


def _make_ctx(params: dict | SSHSprayParams | None = None, dry_run: bool = False) -> ExecutionContext:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="SSH-Spray-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return ExecutionContext(
        execution_id="test-exec-ssh-spray",
        campaign_id=campaign.id,
        target="192.168.56.105",
        params=params or {},
        settings=settings,
        campaign=campaign,
        noise=noise,
        dry_run=dry_run,
    )


class TestSSHSprayModule:
    """Rigorous unit tests for credential.ssh_spray."""

    def test_module_metadata_and_contracts(self):
        mod, _ = _make_module()
        assert mod.MODULE_ID == "credential.ssh_spray"
        assert mod.MODULE_NAME == "SSH Credential Spray & Authentication Audit"
        assert mod.MODULE_CATEGORY == "credential"
        assert mod.OPSEC_LEVEL == OpsecLevel.MEDIUM
        assert mod.PARAMS_MODEL == SSHSprayParams
        assert "T1110.003" in mod.MITRE_TECHNIQUES
        assert "T1021.004" in mod.MITRE_TECHNIQUES

    @pytest.mark.asyncio
    async def test_dry_run_execution(self):
        mod, _ = _make_module()
        ctx = _make_ctx(
            params=SSHSprayParams(
                target="192.168.56.105",
                port=22,
                users=["root", "admin"],
                passwords=["toor", "admin"],
                delay_s=0.1,
            ),
            dry_run=True,
        )
        res = await mod.execute(ctx)
        assert res.status == "dry_run"
        assert res.raw["dry_run"] is True
        assert res.raw["target"] == "192.168.56.105"
        assert res.raw["port"] == 22
        assert "root" in res.raw["candidate_users"]

    @pytest.mark.asyncio
    async def test_spray_finds_valid_credential_via_mock(self):
        mod, _ = _make_module()

        # Mock asyncssh.connect to succeed on 'kali'/'kali' and fail on others
        mock_conn = AsyncMock()
        mock_conn.close = AsyncMock()

        async def mock_connect(host, port, username, password, **kwargs):
            if username == "kali" and password == "kali":
                return mock_conn
            import asyncssh
            raise asyncssh.PermissionDenied("Auth failed")

        with patch("asyncssh.connect", side_effect=mock_connect):
            findings, raw = await mod.run(
                target="192.168.56.105",
                port=22,
                users=["root", "kali", "admin"],
                passwords=["wrongpass", "kali"],
                delay_s=0.0,
                timeout_s=1.0,
                max_attempts=10,
            )

            assert len(raw["valid_credentials"]) == 1
            assert raw["valid_credentials"][0]["username"] == "kali"
            assert raw["valid_credentials"][0]["password"] == "kali"
            assert len(findings) == 1
            assert findings[0].severity == Severity.HIGH
            assert "T1110.003" in findings[0].mitre_technique
            assert findings[0].host == "192.168.56.105"
            assert findings[0].evidence["username"] == "kali"

    @pytest.mark.asyncio
    async def test_spray_exhausts_without_match(self):
        mod, _ = _make_module()

        async def mock_connect_fail(host, port, username, password, **kwargs):
            import asyncssh
            raise asyncssh.PermissionDenied("Auth failed")

        with patch("asyncssh.connect", side_effect=mock_connect_fail):
            findings, raw = await mod.run(
                target="192.168.56.105",
                port=22,
                users=["user1"],
                passwords=["pass1"],
                delay_s=0.0,
                timeout_s=1.0,
                max_attempts=5,
            )

            assert len(raw["valid_credentials"]) == 0
            assert len(findings) == 0
            assert raw["attempts"] == 1
