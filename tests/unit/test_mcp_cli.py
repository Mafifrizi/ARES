"""Unit and integration tests for the ARES MCP CLI interface.

Validates:
- Exit codes: 0 (success), 1 (general error / out-of-scope),
  2 (invalid input/arguments), 130 (SIGINT)
- Machine-readable --json output formats
- NO_COLOR specification (https://no-color.org) compliance
- Non-TTY piped execution safety
- Subcommand help screens and diagnostics
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ares.cli.mcp_cli_utils import (
    EXIT_ERROR,
    EXIT_INVALID_INPUT,
    EXIT_SUCCESS,
    is_no_color_active,
)
from ares.cli.typer_main import app

runner = CliRunner()


def test_mcp_doctor_text() -> None:
    """Verify human-readable doctor diagnostics table."""
    result = runner.invoke(app, ["mcp", "doctor"])
    assert result.exit_code == EXIT_SUCCESS
    assert "ARES MCP Subsystem Readiness Check" in result.stdout
    assert "Protocol Engine" in result.stdout
    assert "Operational Tools" in result.stdout
    assert "Security Gates" in result.stdout


def test_mcp_doctor_json() -> None:
    """Verify machine-readable --json doctor diagnostics output."""
    result = runner.invoke(app, ["mcp", "doctor", "--json"])
    assert result.exit_code == EXIT_SUCCESS
    data = json.loads(result.stdout)
    assert data["status"] == "PASS"
    assert data["healthy"] is True
    assert isinstance(data["subsystems"], list)
    assert len(data["subsystems"]) >= 5


def test_mcp_module_catalog_filtering() -> None:
    """Verify catalog command with category filter."""
    result = runner.invoke(app, ["mcp", "module-catalog", "--category", "ad"])
    assert result.exit_code == EXIT_SUCCESS
    assert "ARES Module Catalog" in result.stdout
    assert "ad.kerberoast" in result.stdout


def test_mcp_module_catalog_json() -> None:
    """Verify machine-readable --json catalog output."""
    result = runner.invoke(app, ["mcp", "module-catalog", "--query", "kerberoast", "--json"])
    assert result.exit_code == EXIT_SUCCESS
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["module_id"] == "ad.kerberoast"
    assert data[0]["category"] == "ad"
    assert "opsec_level" in data[0]


def test_mcp_scope_check_in_scope() -> None:
    """Verify scope-check on authorized IP returns exit code 0."""
    result = runner.invoke(
        app,
        ["mcp", "scope-check", "--target", "10.0.0.5", "--cidr", "10.0.0.0/24"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert "APPROVED" in result.stdout
    assert "YES" in result.stdout


def test_mcp_scope_check_in_scope_json() -> None:
    """Verify scope-check --json output."""
    result = runner.invoke(
        app,
        ["mcp", "scope-check", "--target", "10.0.0.5", "--cidr", "10.0.0.0/24", "--json"],
    )
    assert result.exit_code == EXIT_SUCCESS
    data = json.loads(result.stdout)
    assert data["target"] == "10.0.0.5"
    assert data["in_scope"] is True
    assert data["status"] == "APPROVED"


def test_mcp_scope_check_out_of_scope_strict() -> None:
    """Verify strict scope-check on unauthorized target exits with code 1."""
    result = runner.invoke(
        app,
        ["mcp", "scope-check", "--target", "8.8.8.8", "--cidr", "10.0.0.0/24", "--strict"],
    )
    assert result.exit_code == EXIT_ERROR
    assert "REJECTED_OUT_OF_SCOPE" in result.stdout
    assert "NO" in result.stdout


def test_mcp_scope_check_out_of_scope_non_strict() -> None:
    """Verify non-strict scope-check outputs rejection but exits with code 0."""
    result = runner.invoke(
        app,
        ["mcp", "scope-check", "--target", "8.8.8.8", "--cidr", "10.0.0.0/24", "--no-strict"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert "REJECTED_OUT_OF_SCOPE" in result.stdout


def test_mcp_dry_run_preflight() -> None:
    """Verify pre-flight dry-run card and confirmation token generation."""
    result = runner.invoke(
        app,
        ["mcp", "dry-run", "--target", "10.0.0.5", "--module", "ad.kerberoast"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert "Pre-Flight Dry-Run Card" in result.stdout
    assert "Confirmation Token:" in result.stdout
    assert "ares_tok_" in result.stdout


def test_mcp_dry_run_json() -> None:
    """Verify dry-run --json returns structured simulation payload with token."""
    result = runner.invoke(
        app,
        ["mcp", "dry-run", "--target", "10.0.0.5", "--module", "ad.kerberoast", "--json"],
    )
    assert result.exit_code == EXIT_SUCCESS
    data = json.loads(result.stdout)
    assert data["status"] == "SIMULATION_SUCCESS"
    assert data["module_id"] == "ad.kerberoast"
    assert data["target"] == "10.0.0.5"
    assert data["confirmation_token"].startswith("ares_tok_")
    assert data["token_ttl_seconds"] == 60


def test_mcp_setup_client_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify setup command configures Cursor IDE without error."""
    import tempfile
    orig_cwd = Path.cwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.chdir(tmp_path)
        try:
            result = runner.invoke(app, ["mcp", "setup", "--client", "cursor", "--json"])
            assert result.exit_code == EXIT_SUCCESS
            data = json.loads(result.stdout)
            assert data["client"] == "cursor"
            assert data["status"] == "SUCCESS"
        finally:
            os.chdir(orig_cwd)


def test_mcp_setup_invalid_client() -> None:
    """Verify setup with unsupported client exits with code 2."""
    result = runner.invoke(app, ["mcp", "setup", "--client", "unknown_ide"])
    assert result.exit_code == EXIT_INVALID_INPUT
    assert "Unknown client" in result.stdout


def test_mcp_run_tool_success() -> None:
    """Verify headless execution of an operational MCP tool."""
    result = runner.invoke(app, ["mcp", "run-tool", "ares_list_campaigns", "--json"])
    assert result.exit_code == EXIT_SUCCESS
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["id"] == "camp_default_01"


def test_mcp_run_tool_unknown_tool() -> None:
    """Verify run-tool with unknown tool exits with code 2."""
    result = runner.invoke(app, ["mcp", "run-tool", "nonexistent_ares_tool"])
    assert result.exit_code == EXIT_INVALID_INPUT
    assert "Unknown tool" in result.stdout


def test_mcp_dry_run_invalid_params_json() -> None:
    """Verify invalid JSON params exits with code 2."""
    result = runner.invoke(
        app,
        [
            "mcp",
            "dry-run",
            "--target",
            "10.0.0.5",
            "--module",
            "ad.kerberoast",
            "--params",
            "not_a_valid_json",
        ],
    )
    assert result.exit_code == EXIT_INVALID_INPUT
    assert "Invalid --params JSON" in result.stdout


def test_mcp_no_color_strips_ansi(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify NO_COLOR environment variable adheres to https://no-color.org."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert is_no_color_active() is True
    result = runner.invoke(app, ["mcp", "doctor"])
    assert result.exit_code == EXIT_SUCCESS
    assert "\x1b[" not in result.stdout


def test_mcp_non_interactive_piped() -> None:
    """Verify running mcp without subcommands in piped non-TTY mode does not hang."""
    python_exe = sys.executable
    proc = subprocess.run(  # noqa: S603
        [python_exe, "-m", "ares.cli.main", "mcp"],
        input="",
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == EXIT_SUCCESS
    assert "Non-interactive mode" in proc.stdout or "Status: PASS" in proc.stdout


def test_mcp_subcommand_help_coverage() -> None:
    """Verify comprehensive help is available on all MCP subcommands."""
    subcommands = [
        "console",
        "monitor",
        "tui",
        "doctor",
        "module-catalog",
        "scope-check",
        "dry-run",
        "setup",
        "run-tool",
        "stdio",
        "sse",
        "config",
        "export-tools",
    ]
    for subcmd in subcommands:
        result = runner.invoke(app, ["mcp", subcmd, "--help"])
        assert result.exit_code == EXIT_SUCCESS, f"Subcommand {subcmd} failed help check"
        assert "Usage:" in result.stdout or "Options" in result.stdout


def test_mcp_monitor_options_help() -> None:
    """Verify monitor subcommand flags --campaign, --scope, --demo are documented."""
    import re
    result = runner.invoke(app, ["mcp", "monitor", "--help"], env={"NO_COLOR": "1"})
    assert result.exit_code == EXIT_SUCCESS
    clean_stdout = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.stdout)
    assert "--campaign" in clean_stdout
    assert "--scope" in clean_stdout
    assert "--demo" in clean_stdout
    assert "OpenClaw style" in clean_stdout
