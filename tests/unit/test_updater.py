"""
Unit tests for ARES Secure Platform Update and Upgrade Engine.
Validates multi-layered security protections:
  - Anti-Path Traversal & Path Confinement
  - Blacklisted User Data Protection (Zero Data Loss)
  - URL Whitelist & HTTPS Pinning
  - Pre-flight AST Syntax & Structure Validation
  - Atomic File Replacement with Rollback
  - Additive Update vs In-Place Upgrade Logic
  - POST /modules/reload API Endpoint
"""

import ast
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from ares.api.server import app
from ares.core.updater import (
    ALLOWED_DOMAINS,
    MAX_MODULE_FILE_SIZE,
    ModuleManifestItem,
    PlatformUpdateManager,
    SecurityViolationError,
    UpdateCheckResult,
    UpdateExecutionError,
    atomic_write_file,
    secure_resolve_path,
    secure_verify_url,
    validate_module_code,
)


# ── 1. Security: Path Traversal & Confinement ──────────────────────────────────

def test_secure_resolve_path_valid():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        target = secure_resolve_path(base, "ad/kerberoast.py")
        assert target.is_relative_to(base.resolve())
        assert target.name == "kerberoast.py"


def test_secure_resolve_path_rejects_traversal_double_dots():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        with pytest.raises(SecurityViolationError, match="Path traversal"):
            secure_resolve_path(base, "../outside.py")

        with pytest.raises(SecurityViolationError, match="Path traversal"):
            secure_resolve_path(base, "ad/../../etc/passwd")


def test_secure_resolve_path_rejects_null_bytes():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        with pytest.raises(SecurityViolationError):
            secure_resolve_path(base, "ad/test\x00.py")


# ── 2. Security: User Data Protection & Blacklist ─────────────────────────────

@pytest.mark.parametrize("protected_file", [
    "ares.db",
    "data/custom.sqlite",
    "analytics.sqlite3",
    "production.db",
    ".env",
    "config.yaml",
    "config.yml",
    "ares.yaml",
    "keys/trusted_keys.json",
    "reports/q1_engagement.html",
    "logs/ares.log",
])
def test_secure_resolve_path_rejects_protected_user_data(protected_file):
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        with pytest.raises(SecurityViolationError, match="matches protected user data pattern"):
            secure_resolve_path(base, protected_file)


# ── 3. Security: URL Whitelisting & HTTPS Hard-Pinning ────────────────────────

def test_secure_verify_url_valid_github():
    parsed = secure_verify_url("https://api.github.com/repos/Mafifrizi/ARES/git/trees/main")
    assert parsed.scheme == "https"
    assert parsed.netloc == "api.github.com"

    parsed_raw = secure_verify_url("https://raw.githubusercontent.com/Mafifrizi/ARES/main/ares/modules/ad/kerberoast.py")
    assert parsed_raw.scheme == "https"
    assert parsed_raw.netloc == "raw.githubusercontent.com"


def test_secure_verify_url_rejects_insecure_http():
    with pytest.raises(SecurityViolationError, match="Insecure scheme 'http'"):
        secure_verify_url("http://api.github.com/repos/Mafifrizi/ARES")


def test_secure_verify_url_rejects_untrusted_host():
    with pytest.raises(SecurityViolationError, match="Untrusted host"):
        secure_verify_url("https://evil-third-party.attacker.com/payload.py")

    with pytest.raises(SecurityViolationError, match="Untrusted host"):
        secure_verify_url("https://pastebin.com/raw/xyz123")


# ── 4. Security: Pre-Flight AST Analysis & Syntax Shield ──────────────────────

VALID_MODULE_CODE = '''"""Sample Module"""
from ares.modules.base import BaseModule

class SampleReconModule(BaseModule):
    MODULE_ID = "recon.sample_target"
    MODULE_NAME = "Sample Recon"
    MODULE_CATEGORY = "recon"
'''

def test_validate_module_code_valid():
    valid, msg, mod_id = validate_module_code(VALID_MODULE_CODE)
    assert valid is True
    assert mod_id == "recon.sample_target"


def test_validate_module_code_rejects_syntax_error():
    corrupted_code = '''
    def broken(
        this is total syntax corruption and not valid python
    '''
    valid, msg, mod_id = validate_module_code(corrupted_code)
    assert valid is False
    assert "Syntax error" in msg
    assert mod_id is None


def test_validate_module_code_rejects_missing_class():
    script_only = '''
import os
print("Just an arbitrary script without class")
'''
    valid, msg, mod_id = validate_module_code(script_only)
    assert valid is False
    assert "No class definition found" in msg


def test_validate_module_code_rejects_missing_module_id():
    class_without_id = '''
class UnknownModule:
    pass
'''
    valid, msg, mod_id = validate_module_code(class_without_id)
    assert valid is False
    assert "does not declare a valid MODULE_ID" in msg


def test_validate_module_code_rejects_mismatched_id():
    valid, msg, mod_id = validate_module_code(VALID_MODULE_CODE, expected_module_id="ad.different")
    assert valid is False
    assert "MODULE_ID mismatch" in msg


# ── 5. Atomic File Replacement with Rollback ──────────────────────────────────

def test_atomic_write_file_creates_and_overwrites():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "test_module.py"
        atomic_write_file(target, "content_v1")
        assert target.read_text(encoding="utf-8") == "content_v1"

        atomic_write_file(target, "content_v2")
        assert target.read_text(encoding="utf-8") == "content_v2"


def test_atomic_write_file_automatic_rollback_on_failure():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "important_module.py"
        target.write_text("original_unbroken_content", encoding="utf-8")

        # Simulate exception during os.replace
        with patch("os.replace", side_effect=OSError("Disk write simulated failure")):
            with pytest.raises(UpdateExecutionError):
                atomic_write_file(target, "malformed_or_interrupted_content")

        # Must have restored original content
        assert target.read_text(encoding="utf-8") == "original_unbroken_content"


# ── 6. PlatformUpdateManager Logic ───────────────────────────────────────────

def test_update_modules_dry_run():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "ares" / "modules" / "recon").mkdir(parents=True)
        (root / "ares" / "modules" / "recon" / "existing.py").write_text(VALID_MODULE_CODE, encoding="utf-8")

        mgr = PlatformUpdateManager(project_root=root)

        # Mock check_updates returning 1 new module
        new_item = ModuleManifestItem(
            module_id="cloud.azure_sample",
            relative_path="cloud/azure_sample.py",
            sha256="abc12345",
            size_bytes=1024,
            category="cloud",
        )
        with patch.object(mgr, "check_updates", return_value=UpdateCheckResult(new_modules=[new_item])):
            res = mgr.update_modules(dry_run=True)
            assert res["status"] == "ok"
            assert res["dry_run"] is True
            assert res["installed_count"] == 1
            # File should NOT exist because dry_run=True
            assert not (root / "ares" / "modules" / "cloud" / "azure_sample.py").exists()


def test_upgrade_ui_dry_run():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        dist = root / "frontend" / "dist"
        dist.mkdir(parents=True)
        (dist / "index.html").write_text("<html>old</html>")

        mgr = PlatformUpdateManager(project_root=root)
        res = mgr.upgrade_ui(dry_run=True)
        assert res["status"] == "dry_run"
        assert "[dry-run]" in res["message"]


# ── 7. POST /modules/reload API Endpoint ──────────────────────────────────────

def test_post_modules_reload_loopback():
    saved_modules = dict(sys.modules)
    try:
        with TestClient(app, base_url="http://localhost") as client:
            resp = client.post("/modules/reload")
            assert resp.status_code == 200
            data = resp.json()
            assert data.get("status") == "ok"
            assert data.get("reloaded") is True
            assert "module_count" in data
            assert data["module_count"] >= 1
    finally:
        sys.modules.clear()
        sys.modules.update(saved_modules)


# ── 8. Platform System Upgrade & Diagnostics ──────────────────────────────────

def test_check_system_update_logic():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mgr = PlatformUpdateManager(project_root=root)
        with patch.object(mgr, "_http_get", return_value=b'{"sha":"abc1234567","commit":{"message":"feat: new release","author":{"name":"ARES","date":"2026-09-20"}}}'):
            with patch.object(mgr, "check_updates", return_value=UpdateCheckResult()):
                res = mgr.check_system_update()
                assert res["status"] == "ok"
                assert res["remote_commit"] == "abc1234"
                assert res["commit_message"] == "feat: new release"
                assert "system_update_available" in res


def test_upgrade_system_git_dirty_tree():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / ".git").mkdir()
        mgr = PlatformUpdateManager(project_root=root)

        dirty_output = MagicMock(returncode=0, stdout=" M ares/core/test.py\n")
        with patch("subprocess.run", return_value=dirty_output):
            res = mgr.upgrade_system_git(dry_run=False)
            assert res["status"] == "dirty_tree"
            assert "modified tracked file" in res["message"]


def test_apply_database_migrations_dry_run():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mgr = PlatformUpdateManager(project_root=root)
        res = mgr.apply_database_migrations(dry_run=True)
        assert res["status"] == "dry_run"
        assert "[dry-run]" in res["message"]


def test_run_post_upgrade_diagnostics():
    mgr = PlatformUpdateManager()
    res = mgr.run_post_upgrade_diagnostics()
    assert res["healthy"] is True
    assert len(res["checks"]) >= 3
    subsystems = [c["subsystem"] for c in res["checks"]]
    assert "Core Platform Engine" in subsystems
    assert "Attack Modules" in subsystems


def test_upgrade_all_full_system_workflow():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mgr = PlatformUpdateManager(project_root=root)

        fake_sys = {"status": "ok", "system": {"message": "pulled 1 commit"}, "database": {"applied": True}}
        fake_mods = {"status": "ok", "upgraded_count": 2, "upgraded_modules": ["mod1", "mod2"]}
        fake_add = {"status": "ok", "installed_count": 1, "installed_modules": ["newmod"]}
        fake_ui = {"status": "ok", "message": "UI synced"}

        with patch.object(mgr, "upgrade_system", return_value=fake_sys):
            with patch.object(mgr, "upgrade_modules", return_value=fake_mods):
                with patch.object(mgr, "update_modules", return_value=fake_add):
                    with patch.object(mgr, "upgrade_ui", return_value=fake_ui):
                        with patch.object(mgr, "notify_running_server_reload", return_value={"connected": True, "module_count": 64}):
                            res = mgr.upgrade_all(dry_run=False)
                            assert res["status"] == "ok"
                            assert res["modules_upgraded"] == 2
                            assert res["modules_added"] == 1
                            assert res["system"]["status"] == "ok"
                            assert res["server_reload"]["connected"] is True
                            assert "diagnostics" in res

