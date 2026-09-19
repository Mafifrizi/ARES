"""
Unit tests for ARES CLI 'update' and 'upgrade' subcommands.
"""

from unittest.mock import patch
from typer.testing import CliRunner

from ares.cli.typer_main import app
from ares.core.updater import ModuleManifestItem, UpdateCheckResult

runner = CliRunner()


def test_cli_update_help():
    result = runner.invoke(app, ["update", "--help"])
    assert result.exit_code == 0
    assert "Synchronize and install newly released ARES attack modules" in result.stdout
    assert "--dry-run" in result.stdout
    assert "--module" in result.stdout


def test_cli_upgrade_help():
    result = runner.invoke(app, ["upgrade", "--help"])
    assert result.exit_code == 0
    assert "Upgrade existing ARES modules, Web UI dashboard, or the entire platform" in result.stdout
    assert "--all" in result.stdout
    assert "--ui" in result.stdout
    assert "--modules" in result.stdout
    assert "--dry-run" in result.stdout


def test_cli_update_dry_run_all_installed():
    fake_check = UpdateCheckResult(
        new_modules=[],
        upgradable_modules=[],
        local_count=65,
        remote_count=65,
    )
    with patch("ares.core.updater.PlatformUpdateManager.check_updates", return_value=fake_check):
        result = runner.invoke(app, ["update", "--dry-run"])
        assert result.exit_code == 0
        assert "All official modules are already installed" in result.stdout


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
        result = runner.invoke(app, ["update", "--dry-run"])
        assert result.exit_code == 0
        assert "recon.subdomain_takeover" in result.stdout
        assert "Dry-run complete" in result.stdout


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
        result = runner.invoke(app, ["upgrade", "--all", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry-run simulation completed" in result.stdout


def test_cli_upgrade_ui_dry_run():
    fake_ui_res = {
        "status": "dry_run",
        "message": "[dry-run] Would build or synchronize latest Web UI bundle to frontend/dist/.",
        "target_dir": "frontend/dist",
    }
    with patch("ares.core.updater.PlatformUpdateManager.upgrade_ui", return_value=fake_ui_res):
        result = runner.invoke(app, ["upgrade", "--ui", "--dry-run"])
        assert result.exit_code == 0
        assert "Would build or synchronize" in result.stdout
