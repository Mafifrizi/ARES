from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.windows.lsass_dump import LsassDumpModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="LSASS-Teardown-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return LsassDumpModule(settings=settings, campaign=campaign, noise=noise)


def _mock_impacket_modules(mock_smb_cls):
    mock_impacket = MagicMock()
    mock_smb = MagicMock()
    mock_smb.SMBConnection = mock_smb_cls
    mock_dcerpc = MagicMock()
    mock_scmr = MagicMock()
    mock_transport = MagicMock()

    return {
        "impacket": mock_impacket,
        "impacket.smbconnection": mock_smb,
        "impacket.dcerpc": mock_dcerpc,
        "impacket.dcerpc.v5": mock_dcerpc,
        "impacket.dcerpc.v5.transport": mock_transport,
        "impacket.dcerpc.v5.scmr": mock_scmr,
    }


def test_lsass_dump_local_teardown_normal():
    """MOD-025: local dump file does not exist on disk after normal run completion."""
    mod = _make_module()
    created_local_files = []

    mock_smb_instance = MagicMock()
    mock_smb_instance.getAttributes.return_value.get_filesize.return_value = 1024

    def side_effect_get_file(share, path, write_fn):
        write_fn(b"DUMP_CONTENT_BYTES")

    mock_smb_instance.getFile.side_effect = side_effect_get_file
    mock_smb_cls = MagicMock(return_value=mock_smb_instance)

    mock_mods = _mock_impacket_modules(mock_smb_cls)

    from ares.core.security import secure_mkstemp
    orig_secure_mkstemp = secure_mkstemp

    def tracking_mkstemp(*args, **kwargs):
        path, fd = orig_secure_mkstemp(*args, **kwargs)
        created_local_files.append(path)
        return path, fd

    with patch.dict("sys.modules", mock_mods), \
         patch.object(mod, "_get_lsass_pid", return_value=668), \
         patch.object(mod, "_run_remote_cmd"), \
         patch("time.sleep"), \
         patch.object(mod, "_parse_dump", return_value=[{"username": "Administrator", "nt_hash": "aad3b435b51404eeaad3b435b51404ee"}]), \
         patch("ares.core.security.secure_mkstemp", side_effect=tracking_mkstemp):

        hashes = mod._comsvcs_dump_sync("10.0.0.5", "admin", "pass", "corp.local", "", "")
        assert len(hashes) == 1
        assert len(created_local_files) == 1
        assert not os.path.exists(created_local_files[0]), "Local dump file must be unlinked"
        assert mod._last_dump_data == b"DUMP_CONTENT_BYTES"


def test_lsass_dump_local_teardown_on_crash():
    """MOD-025: local dump file does not exist on disk even if parsing crashes."""
    mod = _make_module()
    created_local_files = []

    mock_smb_instance = MagicMock()
    mock_smb_instance.getAttributes.return_value.get_filesize.return_value = 1024

    def side_effect_get_file(share, path, write_fn):
        write_fn(b"CORRUPTED_DUMP")

    mock_smb_instance.getFile.side_effect = side_effect_get_file
    mock_smb_cls = MagicMock(return_value=mock_smb_instance)
    mock_mods = _mock_impacket_modules(mock_smb_cls)

    from ares.core.security import secure_mkstemp
    orig_secure_mkstemp = secure_mkstemp

    def tracking_mkstemp(*args, **kwargs):
        path, fd = orig_secure_mkstemp(*args, **kwargs)
        created_local_files.append(path)
        return path, fd

    with patch.dict("sys.modules", mock_mods), \
         patch.object(mod, "_get_lsass_pid", return_value=668), \
         patch.object(mod, "_run_remote_cmd"), \
         patch("time.sleep"), \
         patch.object(mod, "_parse_dump", side_effect=RuntimeError("Simulated pypykatz crash")), \
         patch("ares.core.security.secure_mkstemp", side_effect=tracking_mkstemp):

        with pytest.raises(RuntimeError, match="Simulated pypykatz crash"):
            mod._comsvcs_dump_sync("10.0.0.5", "admin", "pass", "corp.local", "", "")

        assert len(created_local_files) == 1
        assert not os.path.exists(created_local_files[0]), "Local dump file must be unlinked after crash"


def test_lsass_pid_remote_cleanup_command_called():
    """MOD-025: remote PID file cleanup command is executed if SMB delete fails or connection drops."""
    mod = _make_module()
    remote_cmds = []

    def tracking_run_remote_cmd(target, username, password, domain, lmhash, nthash, cmd, suffix):
        remote_cmds.append(cmd)

    mock_smb_cls = MagicMock(side_effect=ConnectionResetError("SMB connection lost"))
    mock_mods = _mock_impacket_modules(mock_smb_cls)

    with patch.dict("sys.modules", mock_mods), \
         patch.object(mod, "_run_remote_cmd", side_effect=tracking_run_remote_cmd), \
         patch("time.sleep"):

        pid = mod._get_lsass_pid("10.0.0.5", "admin", "pass", "corp.local", "", "")
        assert pid == 0
        # Check that fallback delete command was issued
        assert any("del /f /q C:\\Windows\\Temp\\ARESPID" in cmd for cmd in remote_cmds)
