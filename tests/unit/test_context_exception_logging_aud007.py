"""
Tests for AUD-007: Verification of structured error logging and explicit return False
when vault.add() or runtime_state.record_finding() raises exceptions.
"""
from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Finding, Severity
from ares.core.context import ExecutionContext


def test_record_credential_vault_exception_logs_error_and_returns_false():
    """When vault.add() raises an unexpected exception, it logs structured error and returns False."""
    mock_vault = MagicMock()
    mock_vault.add.side_effect = RuntimeError("Disk I/O error or vault constraint violation")

    ctx = ExecutionContext(
        target="10.0.0.1",
        module_id="test.module",
        vault=mock_vault,
    )
    ctx.mark_network_io_occurred(True)

    with patch("ares.core.context.logger") as mock_logger:
        res = ctx.record_credential(
            username="target_admin",
            secret="supersecret",
            cred_type="password",
            io_verified=True,
        )

        assert res is False
        mock_logger.error.assert_called_once()
        call_args, call_kwargs = mock_logger.error.call_args
        assert call_args[0] == "vault_record_credential_failed"
        assert call_kwargs.get("username") == "target_admin"
        assert call_kwargs.get("cred_type") == "password"
        assert call_kwargs.get("module_id") == "test.module"
        assert "Disk I/O error" in call_kwargs.get("error", "")
        assert call_kwargs.get("exc_info") is True


def test_record_finding_runtime_state_exception_logs_error_and_returns_false():
    """When runtime_state.record_finding() raises an exception, it logs structured error and returns False."""
    mock_runtime_state = MagicMock()
    mock_runtime_state.record_finding.side_effect = RuntimeError("Runtime state sync failed")

    ctx = ExecutionContext(
        target="10.0.0.1",
        module_id="test.module",
        runtime_state=mock_runtime_state,
    )

    with patch("ares.core.context.logger") as mock_logger:
        res = ctx.record_finding(
            title="Critical SMB Vulnerability",
            severity=Severity.HIGH,
            description="MS17-010 discovered",
        )

        assert res is False
        mock_logger.error.assert_called_once()
        call_args, call_kwargs = mock_logger.error.call_args
        assert call_args[0] == "runtime_state_record_finding_failed"
        assert call_kwargs.get("title") == "Critical SMB Vulnerability"
        assert call_kwargs.get("module_id") == "test.module"
        assert "Runtime state sync failed" in call_kwargs.get("error", "")
        assert call_kwargs.get("exc_info") is True


def test_normal_operation_unaffected():
    """Normal operations for record_finding and record_credential succeed and return expected values."""
    mock_vault = MagicMock()
    mock_vault.add.return_value = {"status": "saved", "id": "cred-1"}

    mock_runtime_state = MagicMock()

    ctx = ExecutionContext(
        target="10.0.0.1",
        module_id="test.module",
        vault=mock_vault,
        runtime_state=mock_runtime_state,
    )
    ctx.mark_network_io_occurred(True)

    # 1. record_finding succeeds
    finding = ctx.record_finding(
        title="Valid Finding",
        severity=Severity.MEDIUM,
    )
    assert isinstance(finding, Finding)
    assert finding.title == "Valid Finding"
    assert len(ctx.findings) == 1
    mock_runtime_state.record_finding.assert_called_once_with(finding)

    # 2. record_credential succeeds
    cred_res = ctx.record_credential(
        username="normal_user",
        secret="validpass",
        cred_type="password",
        io_verified=True,
    )
    assert cred_res == {"status": "saved", "id": "cred-1"}
    mock_vault.add.assert_called_once()
