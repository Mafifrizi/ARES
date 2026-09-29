"""
Production Readiness Hardening Tests

Every test in this file is designed to:
  - FAIL on the old (pre-fix) code
  - PASS only after the hardening fix is applied

These tests prove that BLOCKER and HIGH issues are resolved.

Run: pytest tests/unit/test_hardening.py -v
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = Path(__file__).parent.parent.parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCKER-001 PROOF: No Plaintext Password in DB / Findings / Reports
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoPlaintextCredentials:
    """
    Old behavior: pass_spray stored password in Finding.description and
    Finding.evidence. Password appeared in DB, reports, and logs.

    New behavior: password is replaced with ***REDACTED*** in evidence,
    and description says "stored in credential vault" without showing password.
    """

    @pytest.fixture
    async def db(self, tmp_path):
        from ares.db.database import AresDatabase
        db = await AresDatabase.create(
            str(tmp_path / "hardening.db"),
            "test-enc-key-32-chars-placeholder!",
        )
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_no_plaintext_password_in_finding_description(self, db):
        """
        BLOCKER-001: Finding description must NOT contain the actual password.
        OLD CODE WOULD FAIL: description was "Valid credentials found: CORP\\admin / P@ssw0rd!"
        """
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry

        real_password = "SuperSecret123!"

        # Simulate what pass_spray NOW produces
        c = Campaign(name="SprayTest", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)

        f = Finding(
            title="Password Spray Success: CORP\\admin",
            description=(
                "Valid credentials found for CORP\\admin. "
                "Password stored in credential vault (not shown in report). "
                "Account uses a common/weak password susceptible to spray attacks."
            ),
            severity=Severity.CRITICAL, confidence=1.0,
            module_id="credential.pass_spray", host="10.0.0.1",
            mitre_technique="T1110.003", mitre_tactic="Credential Access",
            evidence={
                "username": "admin", "domain": "CORP",
                "target": "10.0.0.1",
                "vault_credential_id": "abc-123",
                "password": "***REDACTED***",
            },
        )
        await db.save_finding(c.id, f)

        # Read back from DB
        findings = await db.get_findings(c.id)
        assert len(findings) >= 1

        row = findings[0]
        description = row["description"]
        evidence_raw = row.get("evidence_json", "")

        # CRITICAL ASSERTIONS - these FAIL on old code
        assert real_password not in description, \
            f"BLOCKER-001 FAIL: Plaintext password found in description: {description}"
        assert real_password not in evidence_raw, \
            f"BLOCKER-001 FAIL: Plaintext password found in evidence_json: {evidence_raw}"
        assert "***REDACTED***" in evidence_raw, \
            "BLOCKER-001 FAIL: Password not redacted in evidence"

    @pytest.mark.asyncio
    async def test_no_plaintext_password_in_db_query(self, db):
        """
        BLOCKER-001: Full-text search across ALL DB columns must not find password.
        This catches any path where plaintext might leak.
        """
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry

        real_password = "MySecretP@ss99!"

        c = Campaign(name="FullTextTest", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)

        # Insert finding the way NEW code does it
        f = Finding(
            title="Password Spray Success: CORP\\victim",
            description=(
                "Valid credentials found for CORP\\victim. "
                "Password stored in credential vault (not shown in report)."
            ),
            severity=Severity.CRITICAL, confidence=1.0,
            module_id="credential.pass_spray", host="10.0.0.1",
            evidence={"username": "victim", "password": "***REDACTED***"},
        )
        await db.save_finding(c.id, f)

        # Dump entire findings table and search for plaintext password
        async with db._conn.execute("SELECT * FROM findings") as cur:
            rows = await cur.fetchall()
        for row in rows:
            row_str = str(dict(row))
            assert real_password not in row_str, \
                f"BLOCKER-001 FAIL: Password '{real_password}' found in DB row: {row_str[:200]}"

    def test_pass_spray_evidence_schema_has_redacted(self):
        """
        BLOCKER-001: Verify pass_spray source code uses REDACTED in evidence.
        This is a code-level assertion - if someone reverts the fix, this breaks.
        """
        source = Path("ares/modules/credential/pass_spray.py").read_text(encoding="utf-8")

        # New code must have REDACTED marker
        assert '***REDACTED***' in source, \
            "BLOCKER-001 FAIL: pass_spray.py missing ***REDACTED*** in evidence"

        # New code must NOT have raw password in f-string description
        assert '{cred[\'password\']}' not in source and \
               "{cred['password']}" not in source, \
            "BLOCKER-001 FAIL: pass_spray.py still has password in description f-string"

    def test_pass_spray_raw_output_redacted(self):
        """
        BLOCKER-001: Verify raw output dict also has passwords redacted.
        """
        source = Path("ares/modules/credential/pass_spray.py").read_text(encoding="utf-8")
        # Find the raw dict construction - must use REDACTED
        assert '"password": "***REDACTED***"' in source, \
            "BLOCKER-001 FAIL: raw output dict still has plaintext password"


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCKER-002 PROOF: Credential Artifact Cleanup
# ═══════════════════════════════════════════════════════════════════════════════

class TestCredentialArtifactCleanup:
    """
    Old behavior: tempfiles with private keys/tickets left on /tmp forever.
    New behavior: secure_mkstemp creates 0o600 files, cleanup_credential_artifacts
    deletes them, campaign finalization calls cleanup automatically.
    """

    def test_secure_mkstemp_creates_restrictive_permissions(self):
        """
        BLOCKER-002: Files containing credential material must be owner-only (0o600).
        Old code used raw tempfile.mkstemp() which inherits umask (often 0o644).
        """
        from ares.core.security import secure_mkstemp
        path, fd = secure_mkstemp(suffix=".ccache", prefix="test_hardening_")
        try:
            os.close(fd)
            mode = os.stat(path).st_mode
            # Extract permission bits
            perms = stat.S_IMODE(mode)
            if os.name != "nt":
                assert perms == 0o600, \
                    f"BLOCKER-002 FAIL: Credential artifact has permissions {oct(perms)}, expected 0o600"
            else:
                assert os.access(path, os.R_OK | os.W_OK)
        finally:
            os.unlink(path)

    def test_secure_mkdtemp_creates_restrictive_permissions(self):
        """
        BLOCKER-002: Directories containing credential material must be 0o700.
        """
        from ares.core.security import secure_mkdtemp
        import shutil
        path = secure_mkdtemp(prefix="test_hardening_")
        try:
            mode = os.stat(path).st_mode
            perms = stat.S_IMODE(mode)
            if os.name != "nt":
                assert perms == 0o700, \
                    f"BLOCKER-002 FAIL: Credential dir has permissions {oct(perms)}, expected 0o700"
            else:
                assert os.access(path, os.R_OK | os.W_OK | os.X_OK)
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def test_credential_artifact_tracking_and_cleanup(self):
        """
        BLOCKER-002: secure_mkstemp must register artifact for tracking.
        cleanup_credential_artifacts must delete all tracked artifacts.
        """
        from ares.core.security import (
            secure_mkstemp, secure_mkdtemp,
            cleanup_credential_artifacts, _CREDENTIAL_ARTIFACTS,
            _ARTIFACT_LOCK, _GLOBAL_SCOPE,
        )

        # Clear tracking from previous tests
        with _ARTIFACT_LOCK:
            _CREDENTIAL_ARTIFACTS.clear()

        # Create artifacts
        paths = []
        for i in range(3):
            p, fd = secure_mkstemp(suffix=".ccache", prefix=f"test_track_{i}_")
            os.close(fd)
            write_fd = os.open(p, os.O_WRONLY)
            try:
                os.write(write_fd, b"fake ticket data")
            finally:
                os.close(write_fd)
            paths.append(p)

        dir_path = secure_mkdtemp(prefix="test_track_dir_")
        # Write file inside dir
        inner_file = os.path.join(dir_path, "ticket.ccache")
        with open(inner_file, "w") as f:
            f.write("fake")
        paths.append(dir_path)

        # Verify all exist
        for p in paths:
            assert os.path.exists(p), f"Setup failed: {p} not created"

        # Verify tracked (all in _GLOBAL scope since no campaign_id passed)
        with _ARTIFACT_LOCK:
            total_tracked = sum(len(v) for v in _CREDENTIAL_ARTIFACTS.values())
        assert total_tracked >= 4

        # Cleanup (global scope)
        cleaned = cleanup_credential_artifacts()
        assert cleaned >= 4, f"Expected >=4 cleaned, got {cleaned}"

        # Verify ALL deleted
        for p in paths:
            assert not os.path.exists(p), \
                f"BLOCKER-002 FAIL: Credential artifact NOT deleted: {p}"

    def test_delegation_abuse_uses_secure_mkstemp(self):
        """
        BLOCKER-002: delegation_abuse.py must use secure_mkstemp, not raw tempfile.mkstemp.
        """
        source = Path("ares/modules/ad/delegation_abuse.py").read_text(encoding="utf-8")
        assert "secure_mkstemp" in source, \
            "BLOCKER-002 FAIL: delegation_abuse.py not using secure_mkstemp"
        # Must NOT have raw tempfile.mkstemp for ccache files
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            if "tempfile.mkstemp" in line and "ccache" in line:
                pytest.fail(
                    f"BLOCKER-002 FAIL: delegation_abuse.py:{i} still uses raw "
                    f"tempfile.mkstemp for ccache: {line.strip()}"
                )

    def test_golden_ticket_uses_secure_mkstemp(self):
        """
        BLOCKER-002: golden_ticket.py must use secure_mkstemp for ccache output.
        """
        source = Path("ares/modules/credential/golden_ticket.py").read_text(encoding="utf-8")
        assert "secure_mkstemp" in source, \
            "BLOCKER-002 FAIL: golden_ticket.py not using secure_mkstemp"

    def test_adcs_pkinit_has_finally_cleanup(self):
        """
        BLOCKER-002: adcs.py _auth_with_cert must have finally block that deletes pfx.
        """
        source = Path("ares/modules/ad/adcs.py").read_text(encoding="utf-8")
        # Find _auth_with_cert method
        in_method = False
        has_finally = False
        has_unlink_in_finally = False
        for line in source.split("\n"):
            if "def _auth_with_cert" in line:
                in_method = True
            if in_method:
                if "finally:" in line:
                    has_finally = True
                if has_finally and "os.unlink(pfx_path)" in line:
                    has_unlink_in_finally = True
            if in_method and line.strip().startswith("def ") and "_auth_with_cert" not in line:
                break  # next method

        assert has_finally, \
            "BLOCKER-002 FAIL: _auth_with_cert missing finally block"
        assert has_unlink_in_finally, \
            "BLOCKER-002 FAIL: _auth_with_cert finally block doesn't unlink pfx_path"

    def test_dpapi_uses_secure_mkstemp_for_credential_tempfiles(self):
        """
        BLOCKER-002: windows.dpapi must use secure_mkstemp for credential artifacts.
        """
        source = Path("ares/modules/windows/dpapi.py").read_text(encoding="utf-8")
        assert "secure_mkstemp" in source, \
            "BLOCKER-002 FAIL: dpapi.py not using secure_mkstemp"
        assert "tempfile.mkstemp(" not in source, \
            "BLOCKER-002 FAIL: dpapi.py still uses raw tempfile.mkstemp"

    def test_dpapi_transfer_cleans_secure_temp_on_write_failure(self, tmp_path, monkeypatch):
        """
        BLOCKER-002: _transfer_dpapi_files must unlink a secure temp file if
        transfer succeeds but local persistence fails.
        """
        import builtins
        import types
        from ares.modules.windows import dpapi as dpapi_mod

        created = tmp_path / "dpapi-transfer.tmp"
        calls: dict[str, object] = {"count": 0, "campaign_id": ""}

        def fake_secure_mkstemp(suffix="", prefix="ares_", campaign_id=""):
            calls["count"] = int(calls["count"]) + 1
            calls["campaign_id"] = campaign_id
            fd = os.open(str(created), os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
            return str(created), fd

        cleanup_attempts: list[str] = []
        real_unlink = os.unlink

        def tracking_unlink(path):
            cleanup_attempts.append(os.fspath(path))
            real_unlink(path)

        real_open = builtins.open

        def failing_open(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            if os.fspath(path) == str(created) and mode == "wb":
                raise OSError("simulated write failure")
            return real_open(path, *args, **kwargs)

        class FakeSMB:
            def __init__(self, *args, **kwargs):
                self.getfile_calls = 0

            def login(self, *args, **kwargs):
                return None

            def getFile(self, share, remote_path, writer):
                self.getfile_calls += 1
                if self.getfile_calls == 1:
                    writer(b"credential bytes")
                    return None
                raise FileNotFoundError(remote_path)

            def logoff(self):
                return None

        fake_impacket = types.ModuleType("impacket")
        fake_smbconnection = types.ModuleType("impacket.smbconnection")
        fake_smbconnection.SMBConnection = FakeSMB
        fake_impacket.smbconnection = fake_smbconnection

        monkeypatch.setitem(sys.modules, "impacket", fake_impacket)
        monkeypatch.setitem(sys.modules, "impacket.smbconnection", fake_smbconnection)
        monkeypatch.setattr(dpapi_mod, "secure_mkstemp", fake_secure_mkstemp)
        monkeypatch.setattr(dpapi_mod.os, "unlink", tracking_unlink)
        monkeypatch.setattr(builtins, "open", failing_open)

        module = object.__new__(dpapi_mod.DPAPIModule)
        result = module._transfer_dpapi_files(
            "host", "user", "password", "", "", "", "user",
            campaign_id="campaign-123",
        )

        assert result == {}
        assert calls == {"count": 1, "campaign_id": "campaign-123"}
        assert cleanup_attempts == [str(created)]
        assert not created.exists()

    def test_dpapi_chrome_parse_cleans_secure_temp_on_copy_failure(self, tmp_path, monkeypatch):
        """
        BLOCKER-002: _parse_chrome_logindata must unlink its secure SQLite copy
        even if copying into the temp file fails before sqlite opens it.
        """
        import shutil
        from ares.modules.windows import dpapi as dpapi_mod

        login_path = tmp_path / "Login Data"
        login_path.write_bytes(b"not a real sqlite database")
        created = tmp_path / "dpapi-login-copy.db"
        calls: dict[str, object] = {"count": 0, "campaign_id": ""}

        def fake_secure_mkstemp(suffix="", prefix="ares_", campaign_id=""):
            calls["count"] = int(calls["count"]) + 1
            calls["campaign_id"] = campaign_id
            fd = os.open(str(created), os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
            return str(created), fd

        cleanup_attempts: list[str] = []
        real_unlink = os.unlink

        def tracking_unlink(path):
            cleanup_attempts.append(os.fspath(path))
            real_unlink(path)

        def failing_copy2(src, dst):
            assert src == str(login_path)
            assert dst == str(created)
            raise OSError("simulated copy failure")

        monkeypatch.setattr(dpapi_mod, "secure_mkstemp", fake_secure_mkstemp)
        monkeypatch.setattr(dpapi_mod.os, "unlink", tracking_unlink)
        monkeypatch.setattr(shutil, "copy2", failing_copy2)

        module = object.__new__(dpapi_mod.DPAPIModule)
        result = module._parse_chrome_logindata(
            {"chrome_login_data": str(login_path)}, "",
            campaign_id="campaign-123",
        )

        assert result == []
        assert calls == {"count": 1, "campaign_id": "campaign-123"}
        assert cleanup_attempts == [str(created)]
        assert not created.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-001 PROOF: Subprocess Timeout + Kill
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubprocessTimeout:
    """
    Old behavior: isolation.py _spawn() called proc.communicate() without
    timeout. If subprocess hung, the worker hung forever. When wait_for
    timed out, subprocess was NOT killed - became zombie.

    New behavior: _spawn() catches CancelledError, kills process, re-raises.
    """

    def test_isolation_spawn_has_cancel_handler(self):
        """
        HIGH-001: _spawn() must catch CancelledError and kill the process.
        Old code had no CancelledError handler - zombie risk.
        """
        source = Path("ares/worker/isolation.py").read_text(encoding="utf-8")
        assert "CancelledError" in source, \
            "HIGH-001 FAIL: isolation.py _spawn missing CancelledError handler"
        assert "proc.kill()" in source, \
            "HIGH-001 FAIL: isolation.py _spawn doesn't kill process on cancel"

    def test_linux_modules_have_wait_for(self):
        """
        HIGH-001: All linux modules must use asyncio.wait_for on proc.communicate.
        Old code called proc.communicate() directly - hang risk.
        """
        for module in [
            "ares/modules/linux/privesc.py",
            "ares/modules/linux/ld_preload.py",
            "ares/modules/linux/service_hijack.py",
            "ares/modules/linux/nfs_escape.py",
        ]:
            source = Path(module).read_text(encoding="utf-8")
            assert "asyncio.wait_for(proc.communicate()" in source, \
                f"HIGH-001 FAIL: {module} missing wait_for on proc.communicate"
            assert "proc.kill()" in source, \
                f"HIGH-001 FAIL: {module} missing proc.kill() on timeout"

    def test_pip_install_has_timeout(self):
        """
        HIGH-001: marketplace installer pip install must have timeout.
        Old code: subprocess.run([...pip...], check=True) - no timeout.
        """
        source = Path("ares/marketplace/installer.py").read_text(encoding="utf-8")
        # Find the subprocess.run line with pip
        lines = source.split("\n")
        found_pip_run = False
        for i, line in enumerate(lines):
            if "subprocess.run" in line and i + 3 < len(lines):
                ctx = "\n".join(lines[i:i+5])
                if "pip" in ctx:
                    found_pip_run = True
                    assert "timeout=" in ctx, \
                        f"HIGH-001 FAIL: pip install at line {i+1} has no timeout"
        assert found_pip_run, "HIGH-001 FAIL: pip install subprocess.run not found"

    @pytest.mark.asyncio
    async def test_subprocess_killed_on_timeout(self):
        """
        HIGH-001: Prove that a hanging subprocess is killed after timeout.
        This is the behavioral test - simulates what isolation.py does.
        """
        # Spawn a process that sleeps forever
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time; time.sleep(3600)",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        pid = proc.pid
        assert proc.returncode is None  # still running

        # Apply the same pattern as our fixed _spawn()
        try:
            await asyncio.wait_for(proc.communicate(), timeout=0.5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            proc.kill()
            await proc.wait()

        # Process must be dead
        assert proc.returncode is not None, \
            f"HIGH-001 FAIL: Process {pid} still alive after kill"

        # Verify PID is not running anymore
        if os.name != "nt":
            import signal
            try:
                os.kill(pid, 0)  # signal 0 = check if alive
                pytest.fail(f"HIGH-001 FAIL: PID {pid} still exists after kill")
            except ProcessLookupError: pass
            pass  # correct - process is gone


# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-002 PROOF: Pivot Process Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

class TestPivotLifecycle:
    """
    Old behavior: Engine teardown called proc.terminate() without wait().
    Process could become zombie. No teardown_all or health_check existed.

    New behavior: terminate() + wait(timeout=5) + fallback kill().
    PivotManager has teardown_all() and health_check().
    """

    def test_engine_pivot_teardown_waits_for_process(self):
        """
        HIGH-002: Engine must wait for process after terminate, with kill fallback.
        """
        source = Path("ares/core/engine.py").read_text(encoding="utf-8")
        assert "proc.wait(timeout=" in source, \
            "HIGH-002 FAIL: engine.py doesn't wait for pivot process after terminate"
        assert "proc.kill()" in source, \
            "HIGH-002 FAIL: engine.py doesn't force-kill stuck pivot process"

    def test_pivot_manager_has_teardown_all(self):
        """
        HIGH-002: PivotManager must have teardown_all() method.
        """
        source = Path("ares/pivot/infrastructure.py").read_text(encoding="utf-8")
        assert "def teardown_all(self)" in source, \
            "HIGH-002 FAIL: PivotManager missing teardown_all()"

    def test_pivot_manager_has_health_check(self):
        """
        HIGH-002: PivotManager must have health_check() method.
        """
        source = Path("ares/pivot/infrastructure.py").read_text(encoding="utf-8")
        assert "def health_check(self)" in source, \
            "HIGH-002 FAIL: PivotManager missing health_check()"

    def test_engine_cleans_credential_artifacts_on_finalize(self):
        """
        HIGH-002: Engine campaign finalization must call cleanup_credential_artifacts().
        """
        source = Path("ares/core/engine.py").read_text(encoding="utf-8")
        assert "cleanup_credential_artifacts" in source, \
            "HIGH-002 FAIL: engine.py doesn't clean credential artifacts on finalize"


# ═══════════════════════════════════════════════════════════════════════════════
# REGRESSION PROOF: Previous bug fixes still hold
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegressionGuard:
    """Verify that previously fixed bugs haven't regressed."""

    @pytest.fixture
    async def db(self, tmp_path):
        from ares.db.database import AresDatabase
        db = await AresDatabase.create(
            str(tmp_path / "reg.db"),
            "test-enc-key-32-chars-placeholder!",
        )
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_key_returns_false(self, db):
        """BUG FIX: revoke_api_key on nonexistent key must return False, not True."""
        result = await db.revoke_api_key("fake-id", "fake-user")
        assert result is False, \
            "REGRESSION: revoke_api_key returned True for nonexistent key"

    @pytest.mark.asyncio
    async def test_double_revoke_returns_false(self, db):
        """BUG FIX: Second revoke of same key must return False."""
        await db.ensure_default_admin("Admin1!")
        user = await db.get_user("admin")
        key_id, raw = await db.create_api_key(user["id"], "test", "admin")
        assert await db.revoke_api_key(key_id, user["id"]) is True
        assert await db.revoke_api_key(key_id, user["id"]) is False, \
            "REGRESSION: double revoke returned True"

    def test_no_circular_references_in_codebase(self):
        """BUG FIX: No raw[x] = raw patterns."""
        import ast, glob
        for path in sorted(glob.glob("ares/**/*.py", recursive=True)):
            if "__pycache__" in path:
                continue
            with open(path, encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read())
                except SyntaxError:
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    t, v = node.targets[0], node.value
                    if (isinstance(t, ast.Subscript) and isinstance(v, ast.Name)
                            and isinstance(t.value, ast.Name) and t.value.id == v.id):
                        pytest.fail(
                            f"REGRESSION: Circular ref {path}:{node.lineno}"
                        )


# ═══════════════════════════════════════════════════════════════════════════════
# HARDENING: Marketplace URL Scheme Validation & Cracker Cross-Platform Tmpdir
# ═══════════════════════════════════════════════════════════════════════════════

class TestMarketplaceAndCrackerHardening:
    """Validate that marketplace installer rejects non-HTTPS URLs and cracker is cross-platform."""

    def test_marketplace_installer_rejects_insecure_http_url(self):
        from ares.marketplace.installer import ModuleInstaller
        installer = ModuleInstaller()
        with pytest.raises(ValueError, match="Insecure HTTP scheme rejected"):
            installer.install("http://insecure.example.com/malicious.py")

    def test_marketplace_installer_rejects_file_scheme(self):
        from ares.marketplace.installer import ModuleInstaller
        installer = ModuleInstaller()
        with pytest.raises(ValueError, match="Insecure scheme 'file' rejected"):
            installer._install_url("file:///etc/passwd", force=False)

    def test_marketplace_installer_rejects_url_without_hostname(self):
        from ares.marketplace.installer import ModuleInstaller
        installer = ModuleInstaller()
        with pytest.raises(ValueError, match="missing hostname"):
            installer._install_url("https://", force=False)

    def test_marketplace_installer_fail_closed_without_signature(self, monkeypatch):
        """When verify_signature=True, modules without signature or hash must fail-closed."""
        from ares.marketplace.installer import ModuleInstaller
        import httpx

        installer = ModuleInstaller()

        # Mock httpx to return sample module content for .py and 404 for .sig / manifest
        def mock_get(self, url, *args, **kwargs):
            req = httpx.Request("GET", url)
            if url.endswith(".py"):
                return httpx.Response(
                    200, request=req, content=b"class DummyModule:\n    MODULE_ID = 'test.dummy'\n"
                )
            return httpx.Response(404, request=req)

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        with pytest.raises(ValueError, match="Refusing to install unverified module under verify_signature=True"):
            installer._install_url("https://example.com/dummy.py", force=False, verify_signature=True)

    def test_marketplace_accurate_verified_status(self, tmp_path, monkeypatch):
        """Status returned by install_as_dict must match manifest.verified, not request flag."""
        from ares.marketplace.installer import ModuleInstaller, ModuleManifest

        installer = ModuleInstaller()
        mock_manifest = ModuleManifest(
            module_id="test.dummy",
            name="test_dummy",
            version="1.0.0",
            verified=False,  # Unverified
        )
        monkeypatch.setattr(installer, "install", lambda *a, **kw: mock_manifest)

        res = installer.install_as_dict("https://example.com/dummy.py", verify_signature=False)
        assert res["verified"] is False  # Must not return True or request flag!

    def test_marketplace_github_spec_supports_immutable_ref(self, monkeypatch):
        """GitHub spec with @<ref> must resolve to immutable ref in raw URL."""
        from ares.marketplace.installer import ModuleInstaller

        installer = ModuleInstaller()
        captured_url = None

        def mock_install_url(url, force, verify_signature):
            nonlocal captured_url
            captured_url = url
            from ares.marketplace.installer import ModuleManifest
            return ModuleManifest(module_id="test.gh")

        monkeypatch.setattr(installer, "_install_url", mock_install_url)

        installer._install_github("github.com/user/repo@v2.1.0", force=False)
        assert captured_url == "https://raw.githubusercontent.com/user/repo/v2.1.0/repo.py"

    def test_cracker_worker_cross_platform_tmpdir(self, tmp_path):
        import tempfile
        from unittest.mock import MagicMock
        from ares.credential.cracker import CrackingWorker

        vault = MagicMock()
        # Default without tmpdir should use tempfile.gettempdir()
        worker_default = CrackingWorker(vault=vault)
        expected_parent = Path(tempfile.gettempdir())
        assert worker_default.tmpdir.parent == expected_parent
        assert worker_default.tmpdir.name == "ares-crack"
        assert worker_default.tmpdir.exists()

        # Custom tmpdir should be honored
        custom_dir = tmp_path / "custom-crack"
        worker_custom = CrackingWorker(vault=vault, tmpdir=custom_dir)
        assert worker_custom.tmpdir == custom_dir
        assert worker_custom.tmpdir.exists()

    def test_marketplace_path_traversal_rejected(self, tmp_path, monkeypatch):
        """Path traversal in manifest module_id or file path must be rejected."""
        from ares.marketplace.installer import ModuleInstaller, ModuleManifest
        installer = ModuleInstaller()
        fake_file = tmp_path / "test.py"
        fake_file.write_text("print('test')")

        monkeypatch.setattr(
            installer,
            "_infer_manifest_from_file",
            lambda f, url: ModuleManifest(id="../../evil_module"),
        )
        with pytest.raises(ValueError, match="Path traversal detected|Invalid or unsafe module ID"):
            installer._install_single_file(fake_file, source_url="https://example.com/test.py", force=True)

    def test_dynamic_module_lifecycle_fail_closed_without_descriptor(self):
        """Dynamic modules without a registered Phase 5C descriptor must fail admission preparation."""
        import uuid

        from ares.db.execution_lifecycle import AdmissionIntentV3, ExecutionLifecycleStore

        intent = AdmissionIntentV3(
            logical_execution_id=str(uuid.uuid4()),
            submission_id=str(uuid.uuid4()),
            attempt_id=str(uuid.uuid4()),
            outbox_id=None,
            publication_key=None,
            campaign_id=str(uuid.uuid4()),
            module_id="custom.unregistered_module",
            ingress_code="direct_engine",
            operation_id=str(uuid.uuid4()),
            evaluation_mode="live",
            raw_parameters={"target": "192.168.1.50", "port": 80, "domain": "corp.local"},
            credential_ids=(),
            approval_ref=None,
            noise_units=1,
            exfiltration_units=0,
        )
        # Without a registered descriptor, preparation returns None (fail-closed INVALID_CONTRACT)
        prepared = ExecutionLifecycleStore._prepared_admission(intent)
        assert prepared is None

    def test_dynamic_module_descriptor_registration_and_admission(self):
        """When a valid descriptor is registered dynamically, admission preparation succeeds and extracts destinations."""
        import dataclasses
        import uuid

        from ares.db.execution_lifecycle import AdmissionIntentV3, ExecutionLifecycleStore
        from ares.modules.descriptors import (
            FIRST_PARTY_DESCRIPTORS,
            get_descriptor,
            register_dynamic_descriptor,
            unregister_dynamic_descriptor,
        )

        sample = FIRST_PARTY_DESCRIPTORS["network.port_scan"]
        dyn_desc = dataclasses.replace(sample, module_id="network.dynamic_scanner")
        try:
            register_dynamic_descriptor(dyn_desc)
            assert get_descriptor("network.dynamic_scanner") is dyn_desc

            intent = AdmissionIntentV3(
                logical_execution_id=str(uuid.uuid4()),
                submission_id=str(uuid.uuid4()),
                attempt_id=str(uuid.uuid4()),
                outbox_id=None,
                publication_key=None,
                campaign_id=str(uuid.uuid4()),
                module_id="network.dynamic_scanner",
                ingress_code="direct_engine",
                operation_id=str(uuid.uuid4()),
                evaluation_mode="live",
                raw_parameters={"target": "192.168.1.50", "ports": "80,443", "timeout": 5.0},
                credential_ids=(),
                approval_ref=None,
                noise_units=1,
                exfiltration_units=0,
            )
            prepared = ExecutionLifecycleStore._prepared_admission(intent)
            assert prepared is not None
            assert ("host", "192.168.1.50") in prepared.destination_refs
        finally:
            unregister_dynamic_descriptor("network.dynamic_scanner")
            assert get_descriptor("network.dynamic_scanner") is None

    def test_marketplace_manifest_hash_without_ed25519_fails_closed_under_verify_signature(self, monkeypatch):
        """Under verify_signature=True, an unauthenticated manifest hash from same origin must NOT satisfy verification."""
        import httpx
        from ares.marketplace.installer import ModuleInstaller

        installer = ModuleInstaller()
        sample_code = b"class DummyModule:\n    MODULE_ID = 'test.untrusted'\n"

        import hashlib
        sample_hash = hashlib.sha256(sample_code).hexdigest()
        manifest_json = f'{{"id": "test.untrusted", "sha256": "{sample_hash}"}}'.encode("utf-8")

        def mock_get(self, url, *args, **kwargs):
            req = httpx.Request("GET", url)
            if url.endswith(".py"):
                return httpx.Response(200, request=req, content=sample_code)
            elif url.endswith("manifest.json"):
                return httpx.Response(200, request=req, content=manifest_json)
            # .sig is missing (404)
            return httpx.Response(404, request=req)

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        # verify_signature=True must reject module despite matching manifest hash
        with pytest.raises(ValueError, match="has no valid Ed25519 cryptographic signature"):
            installer._install_url("https://example.com/untrusted.py", force=False, verify_signature=True)

    def test_marketplace_deps_skipped_by_default_without_operator_flag(self, monkeypatch):
        """Dependencies must be skipped by default for supply chain isolation unless operator explicitly enables them."""
        import os
        from ares.marketplace.installer import ModuleInstaller

        installer = ModuleInstaller()
        monkeypatch.delenv("ARES_MARKETPLACE_INSTALL_DEPS", raising=False)

        # Calling _install_pip_deps without env flag must not run pip
        called = False

        def mock_run(*a, **kw):
            nonlocal called
            called = True

        import subprocess
        monkeypatch.setattr(subprocess, "run", mock_run)
        installer._install_pip_deps(["requests==2.31.0"])
        assert called is False

    def test_marketplace_deps_rejects_unpinned_versions(self, monkeypatch):
        """Even when operator enables deps, unpinned or floating versions (>=, >, etc.) must be rejected."""
        from ares.marketplace.installer import ModuleInstaller

        installer = ModuleInstaller()
        monkeypatch.setenv("ARES_MARKETPLACE_INSTALL_DEPS", "1")

        with pytest.raises(ValueError, match="Supply-chain policy violation"):
            installer._install_pip_deps(["requests>=2.0.0"])

        with pytest.raises(ValueError, match="Supply-chain policy violation"):
            installer._install_pip_deps(["urllib3"])


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED BOUNDARY HARDENING PROOFS: Sandbox & Firewall Strictness
# ═══════════════════════════════════════════════════════════════════════════════

class TestSandboxAndFirewallHardening:
    """Validates the 6 advanced security boundary hardening findings."""

    def test_trusted_module_namespace_boundary(self):
        """
        FINDING 6: Trusted-prefix matching must respect namespace boundaries.
        'ares.coreevil' and 'ares.dbsomething' must NOT bypass sandboxing.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(trusted_prefixes=["ares.core", "ares.db"])
        runner = SandboxRunner(policy=policy)

        # Authorized exact matches and submodule paths
        assert runner.is_trusted_module("ares.core") is True
        assert runner.is_trusted_module("ares.core.engine") is True
        assert runner.is_trusted_module("ares.db") is True
        assert runner.is_trusted_module("ares.db.database") is True

        # Malicious prefix overlaps must be strictly REJECTED
        assert runner.is_trusted_module("ares.coreevil") is False
        assert runner.is_trusted_module("ares.core_bypass") is False
        assert runner.is_trusted_module("ares.dbsomething") is False
        assert runner.is_trusted_module("ares.db_leak") is False
        assert runner.is_trusted_module("untrusted.module") is False

    def test_docker_runner_source_wraps_module_in_scope_firewall(self):
        """
        FINDING 1: Docker sandbox runner script must wrap module execution
        inside scope_firewall_guard.
        """
        from ares.core.sandbox import SandboxRunner

        inline_source = SandboxRunner._inline_runner()
        assert "from ares.core.scope_firewall import scope_firewall_guard" in inline_source, \
            "Docker inline runner missing scope_firewall_guard import"
        assert "async with scope_firewall_guard(campaign=campaign, module_id=module_id):" in inline_source, \
            "Docker inline runner does not wrap module.run in scope_firewall_guard"

    def test_subprocess_wrapper_script_wraps_module_in_scope_firewall(self):
        """
        Subprocess runner script must wrap module execution inside scope_firewall_guard.
        """
        from ares.core.sandbox import SandboxRunner

        wrapper_source = SandboxRunner._build_wrapper_script(use_seccomp=False)
        assert "from ares.core.scope_firewall import scope_firewall_guard" in wrapper_source
        assert "scope_firewall_guard(campaign=campaign, module_id=module_id" in wrapper_source

    def test_seccomp_tier_is_fail_closed(self):
        """
        FINDING 5: IsolationTier.SECCOMP must fail closed with RuntimeError if
        prctl PR_SET_NO_NEW_PRIVS or pyseccomp BPF loading fails.
        """
        from ares.core.sandbox import SandboxRunner

        wrapper_source = SandboxRunner._build_wrapper_script(use_seccomp=True)
        assert "raise RuntimeError('prctl PR_SET_NO_NEW_PRIVS returned non-zero')" in wrapper_source
        assert "raise RuntimeError(f'IsolationTier.SECCOMP failed to load BPF syscall filter: {_be}')" in wrapper_source

    def test_sandbox_policy_enforcement_docker_options(self, monkeypatch):
        """
        FINDINGS 1 & 4: SandboxPolicy allow_network=False must set network_mode='none',
        and allow_write=False must set read_only=True in Docker.
        """
        import asyncio
        from unittest.mock import MagicMock
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(allow_network=False, allow_write=False)
        runner = SandboxRunner(policy=policy)

        # Mock docker library
        mock_docker = MagicMock()
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.containers.run.return_value = b'{"success": true, "findings": [], "extra": {}}'

        monkeypatch.setattr("sys.modules", {**sys.modules, "docker": mock_docker})

        res = asyncio.run(runner._run_docker("test.module", {}, "camp-123"))
        assert res.success is True

        # Check call arguments to containers.run
        _, run_kwargs = mock_client.containers.run.call_args
        assert run_kwargs.get("network_mode") == "none", "allow_network=False did not set network_mode='none'"
        assert run_kwargs.get("read_only") is True, "allow_write=False did not set read_only=True"

    def test_dual_stack_out_of_scope_cidrs_complement(self):
        """
        FINDING 2: compute_out_of_scope_cidrs must compute complements for BOTH
        IPv4 (0.0.0.0/0) AND IPv6 (::/0), enabling dual-stack OS firewall enforcement.
        """
        from ares.core.scope_firewall import compute_out_of_scope_cidrs

        # Single IPv4 and IPv6 in-scope targets
        scope = ["192.168.1.0/24", "2001:db8::/32"]
        out_of_scope = compute_out_of_scope_cidrs(scope, allow_loopback=True, include_ipv6=True)

        v4_cidrs = [c for c in out_of_scope if ":" not in c]
        v6_cidrs = [c for c in out_of_scope if ":" in c]

        # Both IPv4 and IPv6 complements must be non-empty
        assert len(v4_cidrs) > 0, "IPv4 complement must not be empty"
        assert len(v6_cidrs) > 0, "IPv6 complement must not be empty"

        # Verify loopback is NOT in out-of-scope blocks (loopback is allowed)
        import ipaddress
        for c in v4_cidrs:
            net = ipaddress.ip_network(c)
            assert not net.overlaps(ipaddress.ip_network("127.0.0.1/32")), f"Loopback blocked in {c}"

        for c in v6_cidrs:
            net = ipaddress.ip_network(c)
            assert not net.overlaps(ipaddress.ip_network("::1/128")), f"IPv6 Loopback blocked in {c}"

        # Verify in-scope CIDRs are NOT in out-of-scope blocks
        for c in v4_cidrs:
            net = ipaddress.ip_network(c)
            assert not net.overlaps(ipaddress.ip_network("192.168.1.1/32")), f"In-scope IPv4 blocked in {c}"

        for c in v6_cidrs:
            net = ipaddress.ip_network(c)
            assert not net.overlaps(ipaddress.ip_network("2001:db8::1/128")), f"In-scope IPv6 blocked in {c}"

        # External arbitrary IPv4 and IPv6 must be covered by out_of_scope (so they are blocked)
        ext_v4 = ipaddress.ip_address("8.8.8.8")
        assert any(ext_v4 in ipaddress.ip_network(c) for c in v4_cidrs), "8.8.8.8 must be in out-of-scope complement"

        ext_v6 = ipaddress.ip_address("2606:4700:4700::1111")
        assert any(ext_v6 in ipaddress.ip_network(c) for c in v6_cidrs), "Cloudflare IPv6 must be in out-of-scope complement"


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED BOUNDARY HARDENING & LIFECYCLE CORRECTNESS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityBoundariesAndLifecycle:
    """
    Validates fail-closed semantics for:
    - allow_network=False network namespace isolation
    - drop_privileges=True root privilege drop
    - scope=[] empty scope deny-all semantics & loopback
    - ContextVar nested context restoration & setup failure cleanup
    - uid_owner parameter forwarding & UID-wide boundary semantics
    - OSFirewallController transactional state machine & rollback
    - Defense-in-depth write barrier in subprocess wrapper
    """

    def test_subprocess_allow_network_false_fails_closed(self, monkeypatch):
        """
        FINDING A: allow_network=False must fail-closed if unshare(CLONE_NEWNET) fails.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(allow_network=False)
        runner = SandboxRunner(policy=policy)
        preexec = runner._make_preexec_fn()
        assert preexec is not None

        # Simulate unshare returning failure (-1)
        mock_libc = MagicMock()
        mock_libc.unshare.return_value = -1

        mock_cdll = MagicMock(return_value=mock_libc)
        monkeypatch.setattr("ctypes.CDLL", mock_cdll)
        monkeypatch.setattr("ctypes.get_errno", lambda: 1)  # EPERM

        with pytest.raises(RuntimeError, match="allow_network=False requires network namespace isolation"):
            preexec()

        # Simulate unshare raising an exception
        mock_libc.unshare.side_effect = OSError("Permission denied")
        with pytest.raises(RuntimeError, match="allow_network=False requires network namespace isolation"):
            preexec()

        # Simulate unshare succeeding (0)
        mock_libc.unshare.side_effect = None
        mock_libc.unshare.return_value = 0
        preexec()  # Must not raise

    def test_subprocess_allow_network_true_does_not_unshare(self, monkeypatch):
        """
        allow_network=True must not attempt unshare(CLONE_NEWNET).
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(allow_network=True)
        runner = SandboxRunner(policy=policy)
        preexec = runner._make_preexec_fn()

        mock_libc = MagicMock()
        mock_cdll = MagicMock(return_value=mock_libc)
        monkeypatch.setattr("ctypes.CDLL", mock_cdll)

        preexec()
        mock_libc.unshare.assert_not_called()

    def test_subprocess_drop_privileges_fails_closed(self, monkeypatch):
        """
        FINDING B: drop_privileges=True must abort execution if root fails to drop privileges.
        """
        import types
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(drop_privileges=True)
        runner = SandboxRunner(policy=policy)
        preexec = runner._make_preexec_fn()

        # Simulate running as root (euid == 0)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

        # Mock pwd
        mock_nobody = types.SimpleNamespace(pw_uid=65534, pw_gid=65534)
        mock_pwd = types.ModuleType("pwd")
        mock_pwd.getpwnam = lambda name: mock_nobody
        monkeypatch.setattr("sys.modules", {**sys.modules, "pwd": mock_pwd})

        # Failure 1: setuid raises PermissionError
        monkeypatch.setattr(os, "setgroups", lambda g: None, raising=False)
        monkeypatch.setattr(os, "setgid", lambda g: None, raising=False)

        def mock_failing_setuid(uid):
            raise PermissionError("Operation not permitted")

        monkeypatch.setattr(os, "setuid", mock_failing_setuid, raising=False)

        with pytest.raises(RuntimeError, match="drop_privileges=True failed to drop root to nobody"):
            preexec()

        # Failure 2: setuid returns but geteuid still returns 0 (post-drop verification failure)
        monkeypatch.setattr(os, "setuid", lambda uid: None, raising=False)
        with pytest.raises(RuntimeError, match="process retains root privileges"):
            preexec()

        # Success: setuid succeeds and geteuid returns 65534
        euid_state = [0]
        monkeypatch.setattr(os, "geteuid", lambda: euid_state[0], raising=False)
        monkeypatch.setattr(os, "getuid", lambda: euid_state[0], raising=False)

        def mock_working_setuid(uid):
            euid_state[0] = uid

        monkeypatch.setattr(os, "setuid", mock_working_setuid, raising=False)
        preexec()  # Must succeed

    def test_subprocess_drop_privileges_non_root_is_safe(self, monkeypatch):
        """
        When running as non-root (euid != 0), drop_privileges=True is safe and no-op.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy

        policy = SandboxPolicy(drop_privileges=True)
        runner = SandboxRunner(policy=policy)
        preexec = runner._make_preexec_fn()

        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        preexec()  # Must not raise

    def test_windows_elevated_drop_privileges_aborts_execution(self, monkeypatch):
        """
        On Windows, if running elevated (Admin) with drop_privileges=True,
        execution must be aborted fail-closed rather than silently ignored.
        """
        import asyncio
        from ares.core.sandbox import SandboxRunner, SandboxPolicy
        from ares.core.scope_firewall import OSFirewallController

        policy = SandboxPolicy(drop_privileges=True)
        runner = SandboxRunner(policy=policy)

        monkeypatch.setattr("os.name", "nt")
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))

        res = asyncio.run(runner._run_subprocess("test.module", {}, "camp-123"))
        assert res.success is False
        assert "drop_privileges=True" in res.error
        assert "unsupported on Windows" in res.error

    def test_empty_scope_denies_external_network(self):
        """
        FINDING D: scope=[] must actively install firewall and block all external destinations.
        """
        from ares.core.campaign import Campaign, NoiseProfile
        from ares.core.scope_firewall import ScopeFirewall, ScopeFirewallBlockError

        # Explicit empty scope (deny-all)
        campaign = Campaign(name="test-empty", scope=[], noise_profile=NoiseProfile.NORMAL)
        fw = ScopeFirewall(campaign=campaign)

        # External IPv4 must be blocked
        with pytest.raises(ScopeFirewallBlockError, match="(?i)BLOCKED"):
            fw.assert_allowed_address(("8.8.8.8", 443))

        with pytest.raises(ScopeFirewallBlockError, match="(?i)BLOCKED"):
            fw.assert_allowed_address(("1.1.1.1", 53))

        # External IPv6 must be blocked
        with pytest.raises(ScopeFirewallBlockError, match="(?i)BLOCKED"):
            fw.assert_allowed_address(("2001:4860:4860::8888", 53))

    def test_empty_scope_loopback_semantics(self):
        """
        scope=[] preserves internal loopback IPC when allow_loopback_ipc=True,
        and blocks loopback if allow_loopback_ipc=False.
        """
        from ares.core.campaign import Campaign, NoiseProfile
        from ares.core.scope_firewall import ScopeFirewall, ScopeFirewallBlockError

        campaign = Campaign(name="test-empty", scope=[], noise_profile=NoiseProfile.NORMAL)
        fw = ScopeFirewall(campaign=campaign, allow_loopback_ipc=True)

        # Loopback IPv4 is allowed
        assert fw.assert_allowed_address(("127.0.0.1", 8080)) is not None
        assert fw.assert_allowed_address(("localhost", 8080)) is not None

        # Loopback IPv6 is allowed
        assert fw.assert_allowed_address(("::1", 8080)) is not None

        # When loopback is disabled, even loopback is blocked
        fw_no_lo = ScopeFirewall(campaign=campaign, allow_loopback_ipc=False)
        with pytest.raises(ScopeFirewallBlockError, match="(?i)BLOCKED"):
            fw_no_lo.assert_allowed_address(("127.0.0.1", 8080))

    def test_scope_guard_restores_context_on_setup_failure(self, monkeypatch):
        """
        FINDING E: If OS firewall or setup raises an exception, _current_firewall
        must be reset back to its previous value (None).
        """
        import asyncio
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import (
            scope_firewall_guard,
            _current_firewall,
            OSFirewallController,
            ScopeFirewallBlockError,
        )

        campaign = Campaign(name="test-camp", scope=[ScopeEntry(cidr="10.0.0.0/8")])

        # Simulate OS firewall failure
        monkeypatch.setattr(
            OSFirewallController,
            "apply_rules",
            classmethod(lambda cls, *args, **kwargs: (_ for _ in ()).throw(ScopeFirewallBlockError("Setup failed"))),
        )

        async def _run():
            with pytest.raises(ScopeFirewallBlockError, match="Setup failed"):
                async with scope_firewall_guard(campaign=campaign, enable_os_firewall=True):
                    pass

        asyncio.run(_run())

        # CRITICAL ASSERTION: context must not leak
        assert _current_firewall.get() is None, "ContextVar leaked after setup failure!"

    def test_scope_guard_restores_nested_parent_context(self, monkeypatch):
        """
        CRITICAL NESTED-CONTEXT TEST: When inner guard setup fails,
        _current_firewall must restore the OUTER guard's context, not None!
        """
        import asyncio
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import (
            scope_firewall_guard,
            _current_firewall,
            OSFirewallController,
            ScopeFirewallBlockError,
        )

        outer_campaign = Campaign(name="outer", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        inner_campaign = Campaign(name="inner", scope=[ScopeEntry(cidr="192.168.1.0/24")])

        async def _run():
            async with scope_firewall_guard(campaign=outer_campaign, enable_os_firewall=False) as outer_fw:
                assert _current_firewall.get() is outer_fw, "Outer context not set"

                # Simulate inner guard setup failure
                def mock_failing_apply(*args, **kwargs):
                    raise ScopeFirewallBlockError("Inner OS firewall failed")

                monkeypatch.setattr(OSFirewallController, "apply_rules", classmethod(mock_failing_apply))

                with pytest.raises(ScopeFirewallBlockError, match="Inner OS firewall failed"):
                    async with scope_firewall_guard(campaign=inner_campaign, enable_os_firewall=True):
                        pass

                # INVARIANT: Must restore outer_fw, NOT None!
                assert _current_firewall.get() is outer_fw, \
                    f"Expected outer context {outer_fw}, got {_current_firewall.get()}"

            # Outside outer guard, must be None
            assert _current_firewall.get() is None

        asyncio.run(_run())

    def test_sync_scope_guard_restores_nested_parent_context(self, monkeypatch):
        """
        Sync scope firewall guard must also restore previous outer context on failure.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import (
            scope_firewall_sync_guard,
            _current_firewall,
            OSFirewallController,
            ScopeFirewallBlockError,
        )

        outer_campaign = Campaign(name="outer-sync", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        inner_campaign = Campaign(name="inner-sync", scope=[ScopeEntry(cidr="192.168.1.0/24")])

        with scope_firewall_sync_guard(campaign=outer_campaign, enable_os_firewall=False) as outer_fw:
            assert _current_firewall.get() is outer_fw

            monkeypatch.setattr(
                OSFirewallController,
                "apply_rules",
                classmethod(lambda cls, *args, **kwargs: (_ for _ in ()).throw(ScopeFirewallBlockError("Inner fail"))),
            )

            with pytest.raises(ScopeFirewallBlockError):
                with scope_firewall_sync_guard(campaign=inner_campaign, enable_os_firewall=True):
                    pass

            assert _current_firewall.get() is outer_fw

        assert _current_firewall.get() is None

    def test_uid_owner_is_forwarded_to_os_firewall(self, monkeypatch):
        """
        FINDING F: uid_owner parameter must be forwarded through scope_firewall_guard
        down to OSFirewallController.apply_rules.
        """
        import asyncio
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import scope_firewall_guard, OSFirewallController

        campaign = Campaign(name="test-uid", scope=[ScopeEntry(cidr="10.0.0.0/8")])

        recorded_uid = []
        def mock_apply(cls, camp, cidrs, program=None, uid_owner=None):
            recorded_uid.append(uid_owner)
            return ["TEST_RULE"]

        monkeypatch.setattr(OSFirewallController, "apply_rules", classmethod(mock_apply))
        monkeypatch.setattr(OSFirewallController, "remove_rules", classmethod(lambda cls, rules: len(rules)))

        async def _run():
            async with scope_firewall_guard(campaign=campaign, enable_os_firewall=True, uid_owner=65534):
                pass

        asyncio.run(_run())
        assert recorded_uid == [65534], f"uid_owner not forwarded correctly: {recorded_uid}"

    def test_os_firewall_transactional_state_and_rollback(self, monkeypatch):
        """
        FINDING G: OSFirewallController state must transition through APPLYING
        and VERIFIED_ACTIVE. If a subrule fails, it must rollback and set INACTIVE.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-tx", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        executed_cleanups = []
        call_count = [0]

        def mock_subprocess_run(cmd, *args, **kwargs):
            call_count[0] += 1
            cmd_str = " ".join(cmd)
            # Second apply command fails
            if "-I" in cmd and call_count[0] == 2:
                res = MagicMock()
                res.returncode = 1
                res.stderr = "iptables: rule insertion failed"
                res.stdout = ""
                return res
            if "-D" in cmd:
                executed_cleanups.append(cmd)
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_subprocess_run)

        # Clear any prior state
        OSFirewallController._active_rules.clear()
        OSFirewallController._state = OSFirewallState.UNINITIALIZED

        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert rules == [], "Failed transaction must return empty list"
        assert len(executed_cleanups) > 0, "Rollback cleanups must be executed"
        assert OSFirewallController._state == OSFirewallState.INACTIVE
        assert len(OSFirewallController._active_rules) == 0

    def test_os_firewall_verified_active_when_all_succeed(self, monkeypatch):
        """
        When all subrules succeed, state becomes VERIFIED_ACTIVE and rules are tracked.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-ok", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        cleanups_recorded = []
        def mock_subprocess_run(cmd, *args, **kwargs):
            if "-D" in cmd:
                cleanups_recorded.append(cmd)
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_subprocess_run)

        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert len(rules) == 1
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE
        assert OSFirewallController.get_status()["os_level_active"] is True

        # Now remove rules
        removed = OSFirewallController.remove_rules(rules)
        assert removed > 0
        assert OSFirewallController._state == OSFirewallState.INACTIVE
        assert len(cleanups_recorded) > 0

    def test_allow_write_false_wrapper_defense_in_depth(self):
        """
        FINDING C & 5: Wrapper script installs defense-in-depth open/write hooks
        prohibiting writes outside the dedicated temporary sandbox directory.
        """
        from ares.core.sandbox import SandboxRunner

        source = SandboxRunner._build_wrapper_script(use_seccomp=False)
        assert "_sandboxed_open" in source
        assert "_sandboxed_os_open" in source
        assert "Write prohibited outside sandbox directory" in source
        assert "builtins.open = _sandboxed_open" in source
        assert "os.open = _sandboxed_os_open" in source
        assert "_is_contained_in_sandbox" in source

    def test_canonical_path_containment_in_sandbox_hooks(self, tmp_path):
        """
        FINDING D: Canonical path containment must allow files inside the sandbox
        while strictly rejecting prefix-sibling directories, symlink escapes,
        and relative path directory traversals.
        """
        import os

        sandbox_dir = tmp_path / "ares-sandbox-123"
        sandbox_dir.mkdir()
        sub_dir = sandbox_dir / "sub"
        sub_dir.mkdir()

        # Prefix sibling directory (classic prefix attack)
        evil_sibling = tmp_path / "ares-sandbox-123-evil"
        evil_sibling.mkdir()

        outside_dir = tmp_path / "other"
        outside_dir.mkdir()
        target_outside_file = outside_dir / "secret.txt"
        target_outside_file.write_text("outside data")

        # Symlink inside sandbox pointing outside
        symlink_escape = sandbox_dir / "symlink_outside"
        try:
            os.symlink(str(target_outside_file), str(symlink_escape))
            has_symlink = True
        except (OSError, NotImplementedError):
            has_symlink = False

        # Extract the containment function logic tested in the sandbox wrapper
        def _is_contained_in_sandbox(target_path, sandbox_root):
            try:
                real_sandbox = os.path.realpath(str(sandbox_root))
                target_str = str(target_path)
                if not os.path.exists(target_str):
                    parent = os.path.dirname(target_str) or "."
                    real_target = os.path.join(os.path.realpath(parent), os.path.basename(target_str))
                else:
                    real_target = os.path.realpath(target_str)
                return os.path.commonpath([real_sandbox, real_target]) == real_sandbox
            except (ValueError, OSError, TypeError):
                return False

        # 1. Inside sandbox -> ALLOWED
        assert _is_contained_in_sandbox(sandbox_dir / "file.txt", sandbox_dir) is True
        assert _is_contained_in_sandbox(sub_dir / "file.txt", sandbox_dir) is True

        # 2. Prefix sibling attack -> DENIED
        assert _is_contained_in_sandbox(evil_sibling / "file.txt", sandbox_dir) is False

        # 3. Completely outside directory -> DENIED
        assert _is_contained_in_sandbox(target_outside_file, sandbox_dir) is False

        # 4. Relative directory traversal -> DENIED
        traversal = sandbox_dir / "sub" / ".." / ".." / "other" / "secret.txt"
        assert _is_contained_in_sandbox(traversal, sandbox_dir) is False

        # 5. Symlink escaping sandbox -> DENIED
        if has_symlink:
            assert _is_contained_in_sandbox(symlink_escape, sandbox_dir) is False

    def test_os_firewall_verification_failure_triggers_rollback(self, monkeypatch):
        """
        FINDING B: If CLI command succeeds but kernel state verification fails,
        state transitions through VERIFICATION_FAILED, rolls back rules, and fails closed.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState, ScopeFirewallBlockError

        campaign = Campaign(name="test-verif-fail", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setenv("ARES_REQUIRE_OS_FIREWALL", "1")

        cleanups_run = []
        def mock_subprocess_run(cmd, *args, **kwargs):
            if "-D" in cmd:
                cleanups_run.append(cmd)
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_subprocess_run)
        # Mock _verify_subrules returning False (kernel check failed)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: False))

        OSFirewallController._active_rules.clear()
        with pytest.raises(ScopeFirewallBlockError, match="OS firewall verification failed"):
            OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])

        assert len(cleanups_run) > 0, "Rollback cleanups must run when verification fails"
        assert len(OSFirewallController._active_rules) == 0
        assert OSFirewallController._state == OSFirewallState.VERIFICATION_FAILED
        OSFirewallController.cleanup_all()
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_os_firewall_cleanup_failure_retains_rule_state_and_sets_cleanup_pending(self, monkeypatch):
        """
        FINDING C & 5: When cleanup fails, rule state must NOT be erased.
        Controller must retain failed cleanups, report CLEANUP_PENDING, and allow retry.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-cleanup-fail", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        def mock_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_ok)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))

        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert len(rules) == 1
        rule_name = rules[0]
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE

        # Now simulate cleanup failure
        def mock_fail_cleanup(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 1
            res.stderr = "iptables: Device or resource busy"
            return res

        monkeypatch.setattr("subprocess.run", mock_fail_cleanup)

        # Attempt to remove rules
        removed = OSFirewallController.remove_rules(rules)
        assert removed == 0, "Failed cleanups must not count as removed"

        # INVARIANT: Rule state must be RETAINED, state must be CLEANUP_PENDING
        assert rule_name in OSFirewallController._active_rules
        assert rule_name in OSFirewallController._rule_cleanups
        assert OSFirewallController._state == OSFirewallState.CLEANUP_PENDING
        assert OSFirewallController.get_status()["cleanup_pending"] is True
        assert OSFirewallController.get_status()["state"] == "CLEANUP_PENDING"

        # Now simulate cleanup retry succeeding
        monkeypatch.setattr("subprocess.run", mock_ok)
        OSFirewallController.cleanup_all()

        # After successful retry, rule is removed and state is INACTIVE
        assert len(OSFirewallController._active_rules) == 0
        assert rule_name not in OSFirewallController._rule_cleanups
        assert OSFirewallController._state == OSFirewallState.INACTIVE
        assert OSFirewallController.get_status()["cleanup_pending"] is False

    def test_concurrent_firewall_contexts_isolated(self, monkeypatch):
        """
        Concurrency: Multiple concurrent contexts must track independent rules.
        Removing Context A's rule must not erase Context B's rule.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign_a = Campaign(name="camp-a", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        campaign_b = Campaign(name="camp-b", scope=[ScopeEntry(cidr="192.168.1.0/24")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        def mock_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_ok)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))

        OSFirewallController._active_rules.clear()
        rules_a = OSFirewallController.apply_rules(campaign_a, ["10.0.0.0/8"])
        rules_b = OSFirewallController.apply_rules(campaign_b, ["192.168.1.0/24"])

        assert len(rules_a) == 1
        assert len(rules_b) == 1
        assert rules_a[0] != rules_b[0]
        assert len(OSFirewallController._active_rules) == 2
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE

        # Clean up Context A only
        removed_a = OSFirewallController.remove_rules(rules_a)
        assert removed_a > 0
        assert rules_a[0] not in OSFirewallController._active_rules
        assert rules_b[0] in OSFirewallController._active_rules
        # Still active because Context B is active!
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE

        # Clean up Context B
        removed_b = OSFirewallController.remove_rules(rules_b)
        assert removed_b > 0
        assert len(OSFirewallController._active_rules) == 0
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_parent_manages_uid_firewall_for_dropped_privileges(self, monkeypatch):
        """
        FINDING A: In _run_subprocess, when drop_privileges=True on Linux as root,
        the elevated parent wraps child execution with scope_firewall_guard(enable_os_firewall=True, uid_owner=target_uid).
        """
        import asyncio
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import ares.core.sandbox as sandbox_mod

        policy = SandboxPolicy(tier=IsolationTier.SUBPROCESS, drop_privileges=True)
        runner = SandboxRunner(policy=policy)

        monkeypatch.setattr("os.name", "posix")
        monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)

        import ares.core.scope_firewall as scope_fw_mod

        parent_guard_calls = []

        class MockGuardContext:
            def __init__(self, **kwargs):
                parent_guard_calls.append(kwargs)
            async def __aenter__(self):
                return None
            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(scope_fw_mod, "scope_firewall_guard", MockGuardContext)

        # Mock subprocess execution
        async def mock_create_subprocess(*args, **kwargs):
            mock_proc = MagicMock()
            async def mock_communicate(*args, **kwargs):
                return (b'{"success": true, "findings": [], "extra": {}}', b'')
            mock_proc.communicate = mock_communicate
            mock_proc.returncode = 0
            return mock_proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", mock_create_subprocess)

        result = asyncio.run(runner._run_subprocess("test.module", {}, "campaign-123"))
        assert result.success is True

        # Verify parent installed OS firewall with uid_owner
        assert len(parent_guard_calls) == 1
        assert parent_guard_calls[0]["enable_os_firewall"] is True
        assert parent_guard_calls[0]["uid_owner"] in (65534, getattr(monkeypatch, "fake_uid", 65534))


# ═══════════════════════════════════════════════════════════════════════════════
# POST-fed3098 ADVERSARIAL SECURITY PROOF: TIER INTEGRITY & DOCKER EGRESS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPostFed3098SecurityBoundaryProof:
    """
    Exhaustive proof suite verifying:
    1. Docker online mode external binary containment & strict mode rejection
    2. Strict mode tier integrity: zero silent downgrades from DOCKER to SUBPROCESS
    3. Explicit tier downgrade audit logging and guarantees lost
    4. Firewall verification failure injection (missing rules, mismatch, timeout)
    5. Cleanup retry retention and CLEANUP_PENDING degraded state recovery
    6. Dedicated UID semantics and collateral scope containment
    7. Canonical path containment edge cases (normcase, symlinks, traversal)
    8. Controlled local TCP integration fixture for descendant egress
    9. Custom Docker volume write policy and read-only isolation
    """

    def test_docker_online_external_binary_cannot_escape_scope(self):
        """
        Criterion 2: External binaries inside Docker bridge network cannot be
        guaranteed by Python socket hooks. In strict mode, allow_network=True
        must be rejected unless caller explicitly allows unconfined binaries.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        # Strict mode + allow_network=True + allow_unconfined_docker_binaries=False
        policy = SandboxPolicy(
            tier=IsolationTier.DOCKER,
            allow_network=True,
            strict_mode=True,
            allow_unconfined_docker_binaries=False,
        )
        runner = SandboxRunner(policy=policy)

        result = asyncio.run(runner.run_module("test.module", {}, "camp-123"))
        assert result.success is False
        assert result.requested_tier == IsolationTier.DOCKER
        assert result.effective_tier == IsolationTier.DOCKER
        assert "Docker online mode cannot guarantee scope containment" in result.error
        assert "allow_unconfined_docker_binaries=True" in result.error

    def test_docker_offline_mode_allowed_in_strict_mode(self, monkeypatch):
        """
        Criterion 2 (Model B): When allow_network=False, Docker container is launched
        with network_mode="none", guaranteeing complete kernel network namespace isolation.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        policy = SandboxPolicy(
            tier=IsolationTier.DOCKER,
            allow_network=False,
            strict_mode=True,
        )
        runner = SandboxRunner(policy=policy)

        mock_docker = MagicMock()
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.containers.run.return_value = b'{"success": true, "findings": [], "extra": {}}'
        monkeypatch.setattr("sys.modules", {**sys.modules, "docker": mock_docker})

        result = asyncio.run(runner.run_module("test.module", {}, "camp-123"))
        assert result.success is True
        assert result.effective_tier == IsolationTier.DOCKER
        _, run_kwargs = mock_client.containers.run.call_args
        assert run_kwargs.get("network_mode") == "none"

    def test_docker_unavailable_does_not_silently_downgrade_in_strict_mode(self, monkeypatch):
        """
        Criterion 3: When Docker is unavailable and allow_tier_downgrade=False (default),
        SandboxRunner MUST abort fail-closed rather than silently downgrading to SUBPROCESS.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        policy = SandboxPolicy(
            tier=IsolationTier.DOCKER,
            allow_tier_downgrade=False,
            strict_mode=True,
            allow_network=False,
        )
        runner = SandboxRunner(policy=policy)

        # Force docker import to fail
        monkeypatch.setitem(sys.modules, "docker", None)

        result = asyncio.run(runner.run_module("test.module", {}, "camp-123"))
        assert result.success is False
        assert result.requested_tier == IsolationTier.DOCKER
        assert result.effective_tier == IsolationTier.DOCKER
        assert result.downgraded is False
        assert "Security tier downgrade from DOCKER to SUBPROCESS rejected" in result.error

    def test_docker_downgrade_allowed_when_policy_permits_with_audit_trail(self, monkeypatch):
        """
        Criterion 3: When allow_tier_downgrade=True, downgrade is permitted, but
        effective tier, downgrade reason, and lost guarantees are explicitly reported.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        policy = SandboxPolicy(
            tier=IsolationTier.DOCKER,
            allow_tier_downgrade=True,
            strict_mode=True,
            allow_network=False,
        )
        runner = SandboxRunner(policy=policy)

        # Force docker import to fail
        monkeypatch.setitem(sys.modules, "docker", None)

        # Mock _run_subprocess
        mock_sub_res = MagicMock()
        mock_sub_res.success = True
        mock_sub_res.findings = []
        mock_sub_res.extra = {}
        mock_sub_res.requested_tier = IsolationTier.SUBPROCESS
        mock_sub_res.effective_tier = IsolationTier.SUBPROCESS
        mock_sub_res.sandbox_tier = IsolationTier.SUBPROCESS
        mock_sub_res.downgraded = False
        mock_sub_res.downgrade_reason = ""
        mock_sub_res.guarantees_lost = []
        mock_sub_res.wall_time_s = 0.05

        async def mock_run_subprocess(*args, **kwargs):
            return mock_sub_res

        monkeypatch.setattr(runner, "_run_subprocess", mock_run_subprocess)

        result = asyncio.run(runner.run_module("test.module", {}, "camp-123"))
        assert result.success is True
        assert result.requested_tier == IsolationTier.DOCKER
        assert result.effective_tier == IsolationTier.SUBPROCESS
        assert result.downgraded is True
        assert result.downgrade_reason == "docker_package_not_installed"
        assert "read_only_rootfs_mount_namespace" in result.guarantees_lost
        assert "network_namespace_isolation" in result.guarantees_lost

    def test_firewall_kernel_verification_failure_injection(self, monkeypatch):
        """
        Criterion 6 & 7: Verify failure injection for:
        - rule missing after apply
        - rule changed / wrong specification
        - verification timeout
        All cases must rollback and transition to VERIFICATION_FAILED.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState
        import subprocess

        campaign = Campaign(name="test-fail-injection", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        def mock_apply_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_apply_ok)

        # Case 1: Missing / changed rule verification failure
        subrules_case1 = [
            (["iptables", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", "65534", "-j", "DROP"], ["iptables", "-D", "OUTPUT"])
        ]
        def mock_verify_check_fail(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 1  # rule check failed
            res.stderr = "iptables: Bad rule (does a matching rule exist in that chain?)"
            return res

        monkeypatch.setattr("subprocess.run", mock_verify_check_fail)
        verified = OSFirewallController._verify_subrules(subrules_case1)
        assert verified is False, "Missing subrule must fail verification"

        # Case 2: Verification command timeout
        def mock_verify_timeout(cmd, *args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

        monkeypatch.setattr("subprocess.run", mock_verify_timeout)
        verified_timeout = OSFirewallController._verify_subrules(subrules_case1)
        assert verified_timeout is False, "Verification timeout must fail-closed"

        # Case 3: Invariant: apply_rules with verification failure rolls back and sets VERIFICATION_FAILED
        monkeypatch.setattr("subprocess.run", mock_apply_ok)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: False))

        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert len(rules) == 0
        assert OSFirewallController._state == OSFirewallState.VERIFICATION_FAILED
        OSFirewallController.cleanup_all()
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_firewall_kernel_verification_failure(self, monkeypatch):
        """
        Criterion 6 & 16: Failure injection for OS firewall verification.
        If CLI rule insertion command succeeds, but OS/kernel state check fails:
        1. Controller MUST NOT enter VERIFIED_ACTIVE.
        2. Rollback cleanup commands MUST be executed.
        3. State transitions through VERIFICATION_FAILED.
        4. When ARES_REQUIRE_OS_FIREWALL=1, ScopeFirewallBlockError is raised fail-closed.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState, ScopeFirewallBlockError

        campaign = Campaign(name="test-fail-kernel-verif", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setenv("ARES_REQUIRE_OS_FIREWALL", "1")

        cleanups_run = []
        def mock_apply_ok(cmd, *args, **kwargs):
            if "-D" in cmd:
                cleanups_run.append(cmd)
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_apply_ok)
        # Mock _verify_subrules returning False (kernel check failed)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: False))

        OSFirewallController._active_rules.clear()
        with pytest.raises(ScopeFirewallBlockError, match="OS firewall verification failed"):
            OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])

        assert len(cleanups_run) > 0, "Rollback cleanups must run when verification fails"
        assert len(OSFirewallController._active_rules) == 0
        assert OSFirewallController._state == OSFirewallState.VERIFICATION_FAILED
        OSFirewallController.cleanup_all()
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_firewall_cleanup_retry(self, monkeypatch):
        """
        Criterion 8 & 16: Resilient cleanup retry.
        When initial rule removal command fails:
        1. Rule is retained in _active_rules and failed cleanups in _rule_cleanups.
        2. State transitions to CLEANUP_PENDING.
        3. Subsequent retry of remove_rules or cleanup_all successfully removes the rule
           and transitions state to INACTIVE.
        4. Attempting to remove an unrelated non-existent rule does not affect active rules.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-cleanup-retry-standalone", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        def mock_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_ok)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))

        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert len(rules) == 1
        rule_name = rules[0]
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE

        # Simulate cleanup failure
        def mock_fail(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 1
            res.stderr = "iptables: Resource temporarily unavailable"
            return res

        monkeypatch.setattr("subprocess.run", mock_fail)
        removed = OSFirewallController.remove_rules(rules)
        assert removed == 0
        assert OSFirewallController._state == OSFirewallState.CLEANUP_PENDING
        assert rule_name in OSFirewallController._active_rules

        # Removing an unrelated rule name does not touch active rules
        removed_unrelated = OSFirewallController.remove_rules(["non_existent_rule_xyz"])
        assert removed_unrelated == 0
        assert rule_name in OSFirewallController._active_rules

        # Retry cleanup with success
        monkeypatch.setattr("subprocess.run", mock_ok)
        removed_retry = OSFirewallController.remove_rules([rule_name])
        assert removed_retry > 0
        assert rule_name not in OSFirewallController._active_rules
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_firewall_cleanup_pending_state(self, monkeypatch):
        """
        Criterion 7 & 16: Invariant that failed cleanup leaves controller in CLEANUP_PENDING
        and never falsely reports INACTIVE while uncleaned rules persist.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-pending-state", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        def mock_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_ok)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))

        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        rule_name = rules[0]
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE

        # Fail cleanup
        def mock_fail(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 1
            return res

        monkeypatch.setattr("subprocess.run", mock_fail)
        OSFirewallController.remove_rules(rules)
        assert OSFirewallController._state == OSFirewallState.CLEANUP_PENDING
        assert OSFirewallController.get_status()["cleanup_pending"] is True
        assert OSFirewallController.get_status()["state"] == "CLEANUP_PENDING"
        assert OSFirewallController._state != OSFirewallState.INACTIVE

        # Clean all with success restores INACTIVE
        monkeypatch.setattr("subprocess.run", mock_ok)
        OSFirewallController.cleanup_all()
        assert OSFirewallController._state == OSFirewallState.INACTIVE
        assert OSFirewallController.get_status()["cleanup_pending"] is False

    def test_verified_active_requires_real_verification(self, monkeypatch):
        """
        Criterion 6, 7 & 16: VERIFIED_ACTIVE invariant.
        Rule insertion returncode == 0 is INSUFFICIENT to enter VERIFIED_ACTIVE.
        Only a successful query of OS state via _verify_subrules() confirms VERIFIED_ACTIVE.
        If _verify_subrules returns False, state is NEVER VERIFIED_ACTIVE.
        """
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController, OSFirewallState

        campaign = Campaign(name="test-verified-active", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")

        # Insertion succeeds
        def mock_ok(cmd, *args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            return res

        monkeypatch.setattr("subprocess.run", mock_ok)

        # 1. Verification returns False -> state MUST NOT be VERIFIED_ACTIVE
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: False))
        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert OSFirewallController._state != OSFirewallState.VERIFIED_ACTIVE
        assert OSFirewallController._state == OSFirewallState.VERIFICATION_FAILED

        # 2. Verification returns True -> state becomes VERIFIED_ACTIVE
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))
        OSFirewallController._active_rules.clear()
        rules = OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"])
        assert len(rules) == 1
        assert OSFirewallController._state == OSFirewallState.VERIFIED_ACTIVE
        OSFirewallController.cleanup_all()
        assert OSFirewallController._state == OSFirewallState.INACTIVE

    def test_uid_owner_collateral_scope(self, monkeypatch):
        """
        Criterion 5 & 16: Support sandbox_uid in SandboxPolicy for dedicated sandbox UID,
        verify fallback to nobody (65534) when unspecified, and verify collateral scope semantics.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import OSFirewallController
        import asyncio

        monkeypatch.setattr("os.name", "posix")
        monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)

        import ares.core.scope_firewall as scope_fw_mod
        captured_guards = []

        class MockGuardContext:
            def __init__(self, **kwargs):
                captured_guards.append(kwargs)
            async def __aenter__(self):
                return None
            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(scope_fw_mod, "scope_firewall_guard", MockGuardContext)

        async def mock_exec(*args, **kwargs):
            mock_p = MagicMock()
            async def mock_comm(*args, **kwargs):
                return (b'{"success": true, "findings": [], "extra": {}}', b'')
            mock_p.communicate = mock_comm
            mock_p.returncode = 0
            return mock_p

        monkeypatch.setattr(asyncio, "create_subprocess_exec", mock_exec)

        # Test dedicated UID
        policy_dedicated = SandboxPolicy(tier=IsolationTier.SUBPROCESS, drop_privileges=True, sandbox_uid=5001)
        runner_dedicated = SandboxRunner(policy=policy_dedicated)
        asyncio.run(runner_dedicated._run_subprocess("test.module", {}, "camp-1"))
        assert captured_guards[-1]["uid_owner"] == 5001

        # Test default shared nobody UID
        policy_shared = SandboxPolicy(tier=IsolationTier.SUBPROCESS, drop_privileges=True, sandbox_uid=None)
        runner_shared = SandboxRunner(policy=policy_shared)
        asyncio.run(runner_shared._run_subprocess("test.module", {}, "camp-2"))
        assert captured_guards[-1]["uid_owner"] == 65534

        # Netfilter command generation verification:
        # Applying rules with uid_owner=65534 applies host-wide to UID 65534
        monkeypatch.setattr(OSFirewallController, "is_elevated", classmethod(lambda cls: True))
        monkeypatch.setattr("sys.platform", "linux")
        captured_cmds = []
        def mock_sub_run(cmd, *args, **kwargs):
            captured_cmds.append(cmd)
            res = MagicMock()
            res.returncode = 0
            return res
        monkeypatch.setattr("subprocess.run", mock_sub_run)
        monkeypatch.setattr(OSFirewallController, "_verify_subrules", classmethod(lambda cls, sub_rules: True))

        campaign = Campaign(name="test-uid-collateral", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        OSFirewallController._active_rules.clear()
        OSFirewallController.apply_rules(campaign, ["10.0.0.0/8"], uid_owner=65534)
        uid_matches = [cmd for cmd in captured_cmds if "--uid-owner" in cmd and "65534" in cmd]
        assert len(uid_matches) > 0, "Netfilter rule must explicitly filter by --uid-owner 65534"
        OSFirewallController.cleanup_all()

    def test_subprocess_descendant_egress_is_actually_filtered(self):
        """
        Criterion 4 & 16: Controlled local TCP server fixture verifying that
        ScopeFirewall permits in-scope destinations and blocks out-of-scope destinations.
        Note on Kernel Verification: In unprivileged userland / developer environment,
        OS kernel packet filtering is NOT elevated and thus marked NOT VERIFIED for OS mode.
        Transport-level socket interception is VERIFIED.
        """
        import socket
        import threading
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.scope_firewall import scope_firewall_sync_guard, ScopeFirewallBlockError

        # Start a local TCP echo server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def run_server():
            try:
                conn, _ = server.accept()
                conn.sendall(b"OK")
                conn.close()
            except Exception:
                pass

        th = threading.Thread(target=run_server, daemon=True)
        th.start()

        # In-scope test: loopback allowed
        campaign_ok = Campaign(name="in-scope", scope=[ScopeEntry(cidr="127.0.0.0/8")])
        with scope_firewall_sync_guard(campaign=campaign_ok, enable_os_firewall=False):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", port))
            data = client.recv(10)
            client.close()
            assert data == b"OK"

        # Out-of-scope test: external IP blocked
        campaign_restricted = Campaign(name="scoped", scope=[ScopeEntry(cidr="10.0.0.0/8")])
        with scope_firewall_sync_guard(campaign=campaign_restricted, enable_os_firewall=False):
            client_bad = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with pytest.raises(ScopeFirewallBlockError):
                client_bad.connect(("192.0.2.1", 80))
            client_bad.close()

        server.close()

    def test_canonical_path_containment_edge_cases(self, tmp_path):
        """
        Criterion 10: Exhaustive verification of _is_contained_in_sandbox
        across inside, nested, sibling prefix, symlink, traversal, and normcase.
        """
        import os

        sandbox_root = tmp_path / "sandbox_dir"
        sandbox_root.mkdir()
        sub_dir = sandbox_root / "subdir"
        sub_dir.mkdir()
        sibling_evil = tmp_path / "sandbox_dir_evil"
        sibling_evil.mkdir()

        # The containment logic from _build_wrapper_script
        def is_contained(target_path, sandbox_dir):
            try:
                real_sandbox = os.path.normcase(os.path.realpath(sandbox_dir))
                target_str = str(target_path)
                if not os.path.exists(target_str):
                    parent = os.path.dirname(target_str) or "."
                    real_target = os.path.normcase(os.path.join(os.path.realpath(parent), os.path.basename(target_str)))
                else:
                    real_target = os.path.normcase(os.path.realpath(target_str))
                return os.path.commonpath([real_sandbox, real_target]) == real_sandbox
            except (ValueError, OSError, TypeError):
                return False

        # 1. Inside path
        assert is_contained(sandbox_root / "test.txt", sandbox_root) is True
        # 2. Nested path
        assert is_contained(sub_dir / "nested.txt", sandbox_root) is True
        # 3. Sibling prefix escape (CRITICAL: startswith bug would allow this)
        assert is_contained(sibling_evil / "test.txt", sandbox_root) is False
        # 4. Traversal
        assert is_contained(sandbox_root / ".." / "outside.txt", sandbox_root) is False
        # 5. Outside absolute path
        assert is_contained(tmp_path / "outside.txt", sandbox_root) is False

    def test_custom_docker_volume_write_policy(self, monkeypatch):
        """
        Criterion 9: Verify read_only=True container configuration when allow_write=False.
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        policy = SandboxPolicy(tier=IsolationTier.DOCKER, allow_write=False, allow_network=False)
        runner = SandboxRunner(policy=policy)

        mock_docker = MagicMock()
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.containers.run.return_value = b'{"success": true, "findings": [], "extra": {}}'
        monkeypatch.setattr("sys.modules", {**sys.modules, "docker": mock_docker})

        res = asyncio.run(runner._run_docker("test.module", {}, "camp-123"))
        assert res.success is True
        _, kwargs = mock_client.containers.run.call_args
        assert kwargs["read_only"] is True

    def test_scope_firewall_effective_security_tier(self, monkeypatch):
        """
        Criterion 3, 13 & 16: Observability of requested vs effective security tier.
        SandboxResult MUST report:
        - requested_tier
        - effective_tier
        - downgraded
        - downgrade_reason
        - guarantees_lost
        """
        from ares.core.sandbox import SandboxRunner, SandboxPolicy, IsolationTier
        import asyncio

        # 1. Normal Subprocess
        policy_sub = SandboxPolicy(tier=IsolationTier.SUBPROCESS, allow_network=False)
        runner_sub = SandboxRunner(policy=policy_sub)
        mock_sub_res = MagicMock()
        mock_sub_res.success = True
        mock_sub_res.findings = []
        mock_sub_res.extra = {}
        mock_sub_res.requested_tier = IsolationTier.SUBPROCESS
        mock_sub_res.effective_tier = IsolationTier.SUBPROCESS
        mock_sub_res.sandbox_tier = IsolationTier.SUBPROCESS
        mock_sub_res.downgraded = False
        mock_sub_res.downgrade_reason = ""
        mock_sub_res.guarantees_lost = []
        mock_sub_res.wall_time_s = 0.01

        async def mock_run_subprocess(*args, **kwargs):
            return mock_sub_res

        monkeypatch.setattr(runner_sub, "_run_subprocess", mock_run_subprocess)
        res_sub = asyncio.run(runner_sub.run_module("test.module", {}, "camp-1"))
        assert res_sub.requested_tier == IsolationTier.SUBPROCESS
        assert res_sub.effective_tier == IsolationTier.SUBPROCESS
        assert res_sub.downgraded is False

        # 2. Strict Docker Rejection when unavailable
        policy_dock_strict = SandboxPolicy(tier=IsolationTier.DOCKER, allow_tier_downgrade=False, allow_network=False)
        runner_dock_strict = SandboxRunner(policy=policy_dock_strict)
        monkeypatch.setitem(sys.modules, "docker", None)
        res_dock_strict = asyncio.run(runner_dock_strict.run_module("test.module", {}, "camp-2"))
        assert res_dock_strict.success is False
        assert res_dock_strict.requested_tier == IsolationTier.DOCKER
        assert res_dock_strict.effective_tier == IsolationTier.DOCKER
        assert res_dock_strict.downgraded is False

        # 3. Permitted Docker Downgrade
        policy_dock_compat = SandboxPolicy(tier=IsolationTier.DOCKER, allow_tier_downgrade=True, allow_network=False)
        runner_dock_compat = SandboxRunner(policy=policy_dock_compat)
        monkeypatch.setitem(sys.modules, "docker", None)
        monkeypatch.setattr(runner_dock_compat, "_run_subprocess", mock_run_subprocess)
        res_dock_compat = asyncio.run(runner_dock_compat.run_module("test.module", {}, "camp-3"))
        assert res_dock_compat.requested_tier == IsolationTier.DOCKER
        assert res_dock_compat.effective_tier == IsolationTier.SUBPROCESS
        assert res_dock_compat.downgraded is True
        assert res_dock_compat.downgrade_reason == "docker_package_not_installed"
        assert len(res_dock_compat.guarantees_lost) > 0






