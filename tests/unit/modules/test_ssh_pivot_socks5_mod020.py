"""
Tests for MOD-020: SSHPivot real SOCKS5 dynamic port forwarding.
Verifies:
1. establish_socks5 invokes asyncssh.forward_socks('127.0.0.1', local_port)
2. If asyncssh is unavailable, raises ModuleExecutionError (not a fake dict)
3. If connection or forward_socks fails, raises ModuleExecutionError
4. In run(), socks5_proxy is populated only on verified forward
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.errors import ModuleExecutionError
from ares.core.noise import NoiseController
from ares.modules.lateral.modules import LateralResult, LateralTechnique, SSHPivot


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="SSHPivot-MOD020-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = SSHPivot(settings=settings, campaign=campaign, noise=noise)
    mod._log_context = {}
    return mod


@pytest.mark.asyncio
async def test_establish_socks5_calls_forward_socks():
    """Verify establish_socks5 connects via asyncssh and calls forward_socks on 127.0.0.1:port."""
    mod = _make_module()

    mock_asyncssh = MagicMock()
    mock_conn = AsyncMock()
    mock_listener = MagicMock()
    mock_conn.forward_socks = AsyncMock(return_value=mock_listener)
    mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

    with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
        res = await mod.establish_socks5(
            target="10.0.0.50",
            username="root",
            secret="password123",
            local_port=1080,
            ssh_port=2222,
        )

        assert res["host"] == "127.0.0.1"
        assert res["port"] == 1080
        assert res["type"] == "socks5"
        assert res["via_host"] == "10.0.0.50"

        # Verify asyncssh.connect was called with target host and port
        mock_asyncssh.connect.assert_called_once()
        connect_call = mock_asyncssh.connect.call_args[1]
        assert connect_call["host"] == "10.0.0.50"
        assert connect_call["port"] == 2222
        assert connect_call["username"] == "root"

        # Verify forward_socks called with exact local address and port
        mock_conn.forward_socks.assert_called_once_with("127.0.0.1", 1080)


@pytest.mark.asyncio
async def test_establish_socks5_no_asyncssh_raises_module_execution_error():
    """Verify establish_socks5 raises ModuleExecutionError if asyncssh is not installed."""
    mod = _make_module()

    with patch.dict("sys.modules", {"asyncssh": None}):
        with pytest.raises(ModuleExecutionError) as exc_info:
            await mod.establish_socks5(
                target="10.0.0.50",
                username="root",
                secret="password123",
                local_port=1080,
            )
        assert "asyncssh is not installed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_establish_socks5_connection_failure_raises_module_execution_error():
    """Verify establish_socks5 raises ModuleExecutionError when asyncssh connection fails."""
    mod = _make_module()

    mock_asyncssh = MagicMock()
    mock_asyncssh.connect = AsyncMock(side_effect=OSError("Connection refused"))

    with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
        with pytest.raises(ModuleExecutionError) as exc_info:
            await mod.establish_socks5(
                target="10.0.0.50",
                username="root",
                secret="password123",
                local_port=1080,
            )
        assert "Failed to establish SOCKS5" in str(exc_info.value)


@pytest.mark.asyncio
async def test_sshpivot_run_with_socks_port():
    """Verify run() invokes establish_socks5 when socks_port is passed and move succeeds."""
    mod = _make_module()

    success_lateral = LateralResult(
        technique=LateralTechnique.SSH,
        source_host="operator",
        target_host="10.0.0.50",
        username="root",
        domain="",
        success=True,
        privilege="root",
        output="uid=0(root)",
        duration_ms=50.0,
    )

    fake_proxy = {
        "host": "127.0.0.1",
        "port": 1080,
        "type": "socks5",
        "via_host": "10.0.0.50",
    }

    with patch.object(mod, "move", new_callable=AsyncMock) as mock_move, \
         patch.object(mod, "establish_socks5", new_callable=AsyncMock) as mock_estab, \
         patch.object(mod, "before_request", new_callable=AsyncMock):

        mock_move.return_value = success_lateral
        mock_estab.return_value = fake_proxy

        findings, raw = await mod.run(
            target="10.0.0.50",
            username="root",
            secret="password",
            socks_port=1080,
        )

        mock_estab.assert_called_once_with(
            target="10.0.0.50",
            username="root",
            secret="password",
            local_port=1080,
            ssh_port=22,
            key_path="",
        )
        assert raw["socks5_proxy"] == "socks5://127.0.0.1:1080"
