from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.config import AresSettings
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.noise import NoiseController
from ares.modules.credential.pass_spray import PassSprayModule
from ares.modules.credential.ssh_spray import SSHSprayModule
from ares.modules.credential.pass_the_hash import PassTheHashModule
from ares.modules.credential.reuse import CredentialReuseModule


def make_module(cls):
    settings = AresSettings()
    campaign = Campaign(
        name="Contract-Test",
        client="TestClient",
        operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        domain="corp.local",
        targets=["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "corp.local"],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


def _run(coro):
    return asyncio.run(coro)


REQUIRED_CONTRACT_FIELDS = {
    "username",
    "password",
    "target",
    "port",
    "method",
    "protocol",
    "privilege",
    "domain",
}


def test_pass_spray_valid_credentials_contract():
    """credential.pass_spray outputs unmasked password in raw, masks in finding evidence."""
    mod = make_module(PassSprayModule)

    # Mock SMB success
    fake_smb = MagicMock()
    fake_smb_instance = MagicMock()
    fake_smb.return_value = fake_smb_instance

    with patch.dict("sys.modules", {"impacket.smbconnection": MagicMock(SMBConnection=fake_smb)}):
        findings, raw = _run(
            mod.run(
                target="10.0.0.5",
                domain="corp.local",
                users=["alice"],
                passwords=["Winter2026!"],
                delay_seconds=0.0,
            )
        )

    assert len(raw["valid_credentials"]) == 1
    cred = raw["valid_credentials"][0]
    assert set(cred.keys()) == REQUIRED_CONTRACT_FIELDS
    assert cred["username"] == "alice"
    assert cred["password"] == "Winter2026!"  # unmasked in raw
    assert cred["target"] == "10.0.0.5"
    assert isinstance(cred["port"], int)
    assert cred["port"] == 445
    assert cred["method"] == "password"
    assert cred["protocol"] == "smb"
    assert cred["privilege"] == "user"
    assert cred["domain"] == "corp.local"

    # Verify Finding evidence is masked
    assert len(findings) == 1
    assert findings[0].evidence["password"] == "***REDACTED***"


def test_ssh_spray_valid_credentials_contract():
    """credential.ssh_spray matches 8-field contract with int port."""
    mod = make_module(SSHSprayModule)

    fake_client = MagicMock()
    fake_client.connect.return_value = None
    fake_client.close.return_value = None
    fake_paramiko = MagicMock()
    fake_paramiko.SSHClient.return_value = fake_client

    with patch.dict("sys.modules", {"asyncssh": None, "paramiko": fake_paramiko}):
        findings, raw = _run(
            mod.run(
                target="10.0.0.6",
                port=2222,
                users=["admin"],
                passwords=["AdminSecret!"],
                delay_s=0.0,
            )
        )

    assert len(raw["valid_credentials"]) == 1
    cred = raw["valid_credentials"][0]
    assert set(cred.keys()) == REQUIRED_CONTRACT_FIELDS
    assert cred["username"] == "admin"
    assert cred["password"] == "AdminSecret!"
    assert cred["target"] == "10.0.0.6"
    assert cred["port"] == 2222
    assert isinstance(cred["port"], int)
    assert cred["method"] == "password"
    assert cred["protocol"] == "ssh"
    assert cred["privilege"] == "admin"
    assert cred["domain"] is None
    assert len(findings) == 1


def test_pass_the_hash_valid_credentials_contract():
    """credential.pass_the_hash outputs list[dict], not list[Finding]."""
    mod = make_module(PassTheHashModule)

    fake_smb_instance = MagicMock()
    fake_smb_instance.login.return_value = True
    fake_smb_instance.connectTree.return_value = "tree"
    fake_smb_instance.disconnectTree.return_value = None
    fake_smb_instance.listShares.return_value = [{"shi1_netname": "C$"}]
    fake_smb_cls = MagicMock(return_value=fake_smb_instance)

    with patch.dict("sys.modules", {"impacket.smbconnection": MagicMock(SMBConnection=fake_smb_cls)}):
        findings, raw = _run(
            mod.run(
                target="10.0.0.7",
                username="Administrator",
                domain="corp.local",
                nt_hash="8846f7eaee8fb117ad06bdd830b7586c",
            )
        )

    assert isinstance(raw["valid_credentials"], list)
    assert len(raw["valid_credentials"]) == 1
    cred = raw["valid_credentials"][0]
    assert isinstance(cred, dict)
    assert set(cred.keys()) == REQUIRED_CONTRACT_FIELDS
    assert cred["username"] == "Administrator"
    assert cred["password"] == "8846f7eaee8fb117ad06bdd830b7586c"
    assert cred["target"] == "10.0.0.7"
    assert cred["port"] == 445
    assert isinstance(cred["port"], int)
    assert cred["method"] == "hash"
    assert cred["protocol"] == "smb"
    assert cred["privilege"] == "admin"
    assert cred["domain"] == "corp.local"

    # Finding must still be published
    assert len(findings) == 1
    assert "Pass-the-Hash Successful" in findings[0].title


def test_reuse_valid_credentials_contract():
    """credential.reuse outputs list[dict], not list[str] IDs."""
    mod = make_module(CredentialReuseModule)

    fake_attempt = MagicMock()
    fake_attempt.success = True
    fake_attempt.cred_id = "cred-12345"
    fake_attempt.credential_id = "cred-12345"
    fake_attempt.username = "db_user"
    fake_attempt.domain = "corp.local"
    fake_attempt.target_host = "10.0.0.8"
    fake_attempt.protocol = "winrm"
    fake_attempt.privilege = "user"

    mock_vault = MagicMock()
    mock_vault.get.return_value = MagicMock(is_hash=False)
    mock_vault.reveal.return_value = "DecryptedSecret!"

    fake_engine = MagicMock()
    fake_engine.spray = AsyncMock(return_value=[fake_attempt])
    fake_engine_cls = MagicMock(return_value=fake_engine)

    with patch.dict(
        "sys.modules",
        {
            "ares.credential.reuse": MagicMock(
                ReuseEngine=fake_engine_cls,
                ReuseProtocol=MagicMock(),
            )
        },
    ):
        findings, raw = _run(
            mod.run(
                target="10.0.0.8",
                vault=mock_vault,
                oauth_audit_func=lambda target: {"device_code_permitted": False},
            )
        )

    assert isinstance(raw["valid_credentials"], list)
    assert len(raw["valid_credentials"]) == 1
    cred = raw["valid_credentials"][0]
    assert isinstance(cred, dict)
    assert set(cred.keys()) == REQUIRED_CONTRACT_FIELDS
    assert cred["username"] == "db_user"
    assert cred["password"] == "DecryptedSecret!"
    assert cred["target"] == "10.0.0.8"
    assert cred["port"] == 5985
    assert isinstance(cred["port"], int)
    assert cred["method"] == "password"
    assert cred["protocol"] == "winrm"
    assert cred["privilege"] == "user"
    assert cred["domain"] == "corp.local"

    # Finding must still be published
    assert len(findings) == 1
    assert "Valid credential reused" in findings[0].title
