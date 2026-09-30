"""
Security and regression tests for AUD-003:
Elimination of shell=True, safe subprocess invocation, native Python IO for /proc/keys,
and strict validation of key_id in linux.ccache_hunt.
"""
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux.ccache_hunt import CcacheHuntModule


def _make_module() -> CcacheHuntModule:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Ccache-AUD003-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return CcacheHuntModule(settings=settings, campaign=campaign, noise=noise)


def test_key_id_validation_accepts_valid_integers_and_hex():
    """Valid positive integers and hex strings must be accepted."""
    assert CcacheHuntModule._validate_key_id(12345) == "12345"
    assert CcacheHuntModule._validate_key_id("12345") == "12345"
    assert CcacheHuntModule._validate_key_id("2e3a1f4b") == "2e3a1f4b"
    assert CcacheHuntModule._validate_key_id("0x2e3a1f4b") == "0x2e3a1f4b"
    assert CcacheHuntModule._validate_key_id(0) == "0"


def test_key_id_validation_rejects_negative_and_malformed():
    """Negative values and invalid inputs must raise ValueError."""
    with pytest.raises(ValueError):
        CcacheHuntModule._validate_key_id(-1)

    with pytest.raises(ValueError):
        CcacheHuntModule._validate_key_id("-50")

    with pytest.raises(ValueError):
        CcacheHuntModule._validate_key_id("")

    with pytest.raises(ValueError):
        CcacheHuntModule._validate_key_id("   ")


def test_key_id_validation_rejects_shell_metacharacters():
    """Key IDs containing shell injection metacharacters must be rejected."""
    for bad_id in [
        "123; rm -rf /",
        "2e3a1f4b | whoami",
        "123`id`",
        "$(whoami)",
        "123 && cat /etc/passwd",
        "123\nid",
    ]:
        with pytest.raises(ValueError):
            CcacheHuntModule._validate_key_id(bad_id)


def test_execute_command_strictly_enforces_shell_false():
    """Subprocess execution must use shell=False and pass arguments as a list."""
    mod = _make_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="mocked_keyctl_output\n")

        # Even if a command has metacharacters, it MUST be passed as literal argument array
        # and shell=False MUST be used so the shell is never invoked
        malicious_key_id = "12345; cat /etc/shadow"
        out = mod._execute_command(["keyctl", "print", malicious_key_id])

        assert mock_run.called
        call_args, call_kwargs = mock_run.call_args
        assert call_kwargs.get("shell") is False
        assert call_args[0] == ["keyctl", "print", malicious_key_id]
        assert out == "mocked_keyctl_output\n"


@pytest.mark.asyncio
async def test_proc_keys_permission_denied_handled_gracefully_native():
    """When /proc/keys throws PermissionError on native read, module must handle gracefully."""
    mod = _make_module()

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", side_effect=PermissionError("Permission denied")), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            target="10.0.0.50",
            scan_kcm_socket=False,
            search_dirs=[],
        )

        assert len(findings) == 1
        assert "Inaccessible" in findings[0].title
        assert findings[0].confidence == 0.35
        assert raw["tickets"][0]["permission_denied"] is True
        assert raw["tickets"][0]["file_path"] == "/proc/keys"


@pytest.mark.asyncio
async def test_proc_keys_filtered_in_python_native():
    """Verification that native /proc/keys reading filters kerberos lines in Python."""
    mod = _make_module()

    fake_proc_keys = (
        "00000001 2/2 1 1d 3f030000 1000 1000 user some_random_key:data\n"
        "2e3a1f4b 2/2 1 1d 3f030000 1000 1000 user krb_ccache:corpadmin@CORP.LOCAL\n"
        "00000002 2/2 1 1d 3f030000 1000 1000 user ssh_auth_socket:data\n"
    )

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=fake_proc_keys)), \
         patch.object(mod, "_execute_command", return_value="TICKET_BYTES_HEX_TEST"), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            target="10.0.0.50",
            scan_kcm_socket=False,
            search_dirs=[],
        )

        # Only the krb_ccache key must be processed, ignoring ssh and random keys
        assert len(raw["tickets"]) == 1
        ticket = raw["tickets"][0]
        assert "corpadmin" in ticket["client"]
        assert ticket["keydata"] == "TICKET_BYTES_HEX_TEST"
