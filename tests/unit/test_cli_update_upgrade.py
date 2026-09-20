"""
Unit tests for ARES CLI 'update' and 'upgrade' subcommands.
"""

import re
from unittest.mock import patch
from typer.testing import CliRunner

from ares.cli.typer_main import app
from ares.core.updater import ModuleManifestItem, UpdateCheckResult

runner = CliRunner()


def _clean(text: str) -> str:
    """Strip ANSI escape sequences from CLI output."""
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def test_cli_update_help():
    result = runner.invoke(app, ["update", "--help"], env={"NO_COLOR": "1"})
    assert result.exit_code == 0
    out = _clean(result.stdout)
    assert "Synchronize and install newly released ARES attack modules" in out
    assert "--dry-run" in out
    assert "--module" in out


def test_cli_upgrade_help():
    result = runner.invoke(app, ["upgrade", "--help"], env={"NO_COLOR": "1"})
    assert result.exit_code == 0
    out = _clean(result.stdout)
    assert "Upgrade ARES core platform system, database schemas" in out
    assert "--all" in out
    assert "--system" in out
    assert "--check" in out
    assert "--ui" in out
    assert "--modules" in out
    assert "--dry-run" in out


def test_cli_update_dry_run_all_installed():
    fake_check = UpdateCheckResult(
        new_modules=[],
        upgradable_modules=[],
        local_count=65,
        remote_count=65,
    )
    with patch("ares.core.updater.PlatformUpdateManager.check_updates", return_value=fake_check):
        result = runner.invoke(app, ["update", "--dry-run"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "All official modules are already installed" in out


def test_cli_update_dry_run_with_new_module():
    new_item = ModuleManifestItem(
        module_id="recon.subdomain_takeover",
        relative_path="recon/subdomain_takeover.py",
        sha256="123456",
        size_bytes=4096,
        category="recon",
    )
    fake_check = UpdateCheckResult(
        new_modules=[new_item],
        local_count=65,
        remote_count=66,
    )
    with patch("ares.core.updater.PlatformUpdateManager.check_updates", return_value=fake_check):
        result = runner.invoke(app, ["update", "--dry-run"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "recon.subdomain_takeover" in out
        assert "Dry-run complete" in out


def test_cli_upgrade_dry_run_all():
    fake_all_res = {
        "status": "ok",
        "modules_upgraded": 2,
        "modules_added": 1,
        "ui_status": "ok",
        "server_reload": {"connected": False},
        "dry_run": True,
    }
    with patch("ares.core.updater.PlatformUpdateManager.upgrade_all", return_value=fake_all_res):
        result = runner.invoke(app, ["upgrade", "--all", "--dry-run"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "Dry-run simulation completed" in out


def test_cli_upgrade_ui_dry_run():
    fake_ui_res = {
        "status": "dry_run",
        "message": "[dry-run] Would build or synchronize latest Web UI bundle to frontend/dist/.",
        "target_dir": "frontend/dist",
    }
    with patch("ares.core.updater.PlatformUpdateManager.upgrade_ui", return_value=fake_ui_res):
        result = runner.invoke(app, ["upgrade", "--ui", "--dry-run"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "Would build or synchronize" in out


def test_cli_upgrade_check():
    fake_chk = {
        "status": "ok",
        "version": "6.0.0",
        "branch": "main",
        "local_commit": "fa91f1a",
        "remote_commit": "fa91f1a",
        "commit_date": "2026-09-20T00:00:00Z",
        "commit_message": "feat: full platform upgrade",
        "system_update_available": False,
        "new_modules_count": 0,
        "upgradable_modules_count": 0,
        "ui_available": True,
    }
    with patch("ares.core.updater.PlatformUpdateManager.check_system_update", return_value=fake_chk):
        result = runner.invoke(app, ["upgrade", "--check"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "ARES Platform System Status" in out
        assert "6.0.0" in out
        assert "Up to date" in out


def test_cli_upgrade_system_dry_run():
    fake_sys = {
        "status": "dry_run",
        "system": {"message": "[dry-run] Would pull 1 commit"},
        "database": {"message": "[dry-run] Would apply migrations"},
    }
    with patch("ares.core.updater.PlatformUpdateManager.upgrade_system", return_value=fake_sys):
        result = runner.invoke(app, ["upgrade", "--system", "--dry-run"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "Core Engine & DB" in out
        assert "Dry-run simulation completed" in out


def test_cli_upgrade_full_system_execution():
    fake_all = {
        "status": "ok",
        "system": {
            "status": "ok",
            "system": {"message": "pulled 2 commits"},
            "database": {"applied": True, "message": "Head migrated"},
        },
        "modules_upgraded": 3,
        "modules_added": 1,
        "ui_status": "ok",
        "server_reload": {"connected": True, "module_count": 64},
        "diagnostics": {
            "healthy": True,
            "checks": [
                {"subsystem": "Core Framework", "detail": "Clean"},
                {"subsystem": "Database Storage", "detail": "Online"},
            ],
        },
        "dry_run": False,
    }
    with patch("ares.core.updater.PlatformUpdateManager.upgrade_all", return_value=fake_all):
        result = runner.invoke(app, ["upgrade", "--all"], env={"NO_COLOR": "1"})
        assert result.exit_code == 0
        out = _clean(result.stdout)
        assert "Platform System Upgrade Completed" in out
        assert "Core Framework: Updated" in out
        assert "Database Schema: Migrated (head)" in out
        assert "3 updated" in out
        assert "1 new added" in out
        assert "Live Server Hot-Reload: Connected" in out
        assert "Post-Upgrade System Diagnostics: HEALTHY" in out

