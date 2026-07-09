"""
FINAL Hardening Tests — Last line of defense.

Tests campaign-scoped artifact isolation, guaranteed cleanup on all paths,
exception safety, and long-running accumulation prevention.

Run: pytest tests/unit/test_final_hardening.py -v
"""
from __future__ import annotations

import asyncio
import os
import stat
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent.parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class TestCampaignScopedCleanup:
    """Prove that artifact cleanup is campaign-isolated."""

    def _reset_tracking(self):
        from ares.core.security import _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK
        with _ARTIFACT_LOCK:
            _CREDENTIAL_ARTIFACTS.clear()

    def test_no_cross_campaign_artifact_deletion(self):
        """
        Campaign A cleanup must NOT delete Campaign B's artifacts.
        Old code: flat list → cleanup deletes everything.
        New code: dict[campaign_id] → scoped cleanup.
        """
        from ares.core.security import (
            secure_mkstemp, cleanup_credential_artifacts,
        )
        self._reset_tracking()

        # Campaign A creates 2 artifacts
        a1, fd1 = secure_mkstemp(suffix=".ccache", prefix="camp_a_", campaign_id="campaign-A")
        os.close(fd1)
        a2, fd2 = secure_mkstemp(suffix=".ccache", prefix="camp_a_", campaign_id="campaign-A")
        os.close(fd2)

        # Campaign B creates 2 artifacts
        b1, fd3 = secure_mkstemp(suffix=".ccache", prefix="camp_b_", campaign_id="campaign-B")
        os.close(fd3)
        b2, fd4 = secure_mkstemp(suffix=".ccache", prefix="camp_b_", campaign_id="campaign-B")
        os.close(fd4)

        # All 4 exist
        for p in [a1, a2, b1, b2]:
            assert os.path.exists(p), f"Setup: {p} not created"

        # Cleanup Campaign A
        cleaned = cleanup_credential_artifacts("campaign-A")
        assert cleaned == 2

        # Campaign A's files gone
        assert not os.path.exists(a1), f"Campaign A artifact NOT deleted: {a1}"
        assert not os.path.exists(a2), f"Campaign A artifact NOT deleted: {a2}"

        # Campaign B's files MUST still exist
        assert os.path.exists(b1), \
            f"CRITICAL: Campaign B artifact DELETED by Campaign A cleanup: {b1}"
        assert os.path.exists(b2), \
            f"CRITICAL: Campaign B artifact DELETED by Campaign A cleanup: {b2}"

        # Now cleanup B
        cleaned_b = cleanup_credential_artifacts("campaign-B")
        assert cleaned_b == 2
        assert not os.path.exists(b1)
        assert not os.path.exists(b2)

    def test_cleanup_all_cleans_every_campaign(self):
        """cleanup_all_credential_artifacts() must clean ALL campaigns."""
        from ares.core.security import (
            secure_mkstemp, cleanup_all_credential_artifacts,
        )
        self._reset_tracking()

        paths = []
        for camp in ["c1", "c2", "c3"]:
            p, fd = secure_mkstemp(suffix=".test", prefix=f"{camp}_", campaign_id=camp)
            os.close(fd)
            paths.append(p)

        total = cleanup_all_credential_artifacts()
        assert total == 3, f"Expected 3 cleaned, got {total}"
        for p in paths:
            assert not os.path.exists(p), f"Artifact survived cleanup_all: {p}"

    def test_global_scope_isolation(self):
        """Artifacts created without campaign_id go to _GLOBAL scope."""
        from ares.core.security import (
            secure_mkstemp, cleanup_credential_artifacts,
            _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK, _GLOBAL_SCOPE,
        )
        self._reset_tracking()

        # Create without campaign_id
        p, fd = secure_mkstemp(suffix=".test", prefix="global_")
        os.close(fd)

        with _ARTIFACT_LOCK:
            assert _GLOBAL_SCOPE in _CREDENTIAL_ARTIFACTS
            assert p in _CREDENTIAL_ARTIFACTS[_GLOBAL_SCOPE]

        # Cleanup with empty campaign_id cleans global scope
        cleaned = cleanup_credential_artifacts()
        assert cleaned == 1
        assert not os.path.exists(p)


class TestCleanupGuarantee:
    """Prove cleanup runs on ALL execution paths."""

    def _reset_tracking(self):
        from ares.core.security import _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK
        with _ARTIFACT_LOCK:
            _CREDENTIAL_ARTIFACTS.clear()

    def test_secure_mkstemp_reopenable_after_close(self):
        """Windows ACL hardening must not make the temp file unusable."""
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        p, fd = secure_mkstemp(suffix=".ccache", campaign_id="reopen-test")
        os.close(fd)
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write("ticket data")
            with open(p, encoding="utf-8") as f:
                assert f.read() == "ticket data"
        finally:
            cleanup_credential_artifacts("reopen-test")

    def test_cleanup_always_runs_on_success(self):
        """Cleanup works after successful operation."""
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        p, fd = secure_mkstemp(suffix=".ccache", campaign_id="success-test")
        os.close(fd)
        with open(p, "w") as f:
            f.write("ticket data")

        assert os.path.exists(p)
        cleanup_credential_artifacts("success-test")
        assert not os.path.exists(p), "Cleanup failed on success path"

    def test_cleanup_always_runs_on_exception(self):
        """Cleanup works even when exception occurred between create and cleanup."""
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        p, fd = secure_mkstemp(suffix=".pfx", campaign_id="exc-test")
        os.close(fd)
        with open(p, "wb") as f:
            f.write(b"private key material")

        # Simulate exception in module code
        try:
            raise RuntimeError("Module crashed!")
        except RuntimeError:
            pass  # Module failed, but cleanup must still work

        cleanup_credential_artifacts("exc-test")
        assert not os.path.exists(p), \
            "CRITICAL: Artifact NOT cleaned after exception"

    def test_exception_does_not_skip_cleanup(self):
        """
        Simulate a full module execution with try/finally pattern.
        Artifact must be deleted even if module raises.
        """
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        artifact_path = None
        campaign = "finally-test"

        try:
            p, fd = secure_mkstemp(suffix=".ccache", campaign_id=campaign)
            os.close(fd)
            artifact_path = p

            # Simulate module work that crashes
            raise ValueError("LDAP connection failed")
        except ValueError:
            pass
        finally:
            cleanup_credential_artifacts(campaign)

        assert artifact_path is not None
        assert not os.path.exists(artifact_path), \
            "CRITICAL: Artifact survived exception + finally cleanup"

    def test_cleanup_idempotent(self):
        """Double cleanup must not crash or return wrong count."""
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        p, fd = secure_mkstemp(suffix=".test", campaign_id="idem-test")
        os.close(fd)

        assert cleanup_credential_artifacts("idem-test") == 1
        assert cleanup_credential_artifacts("idem-test") == 0  # already cleaned
        # Must not raise

    def test_cleanup_nonexistent_campaign(self):
        """Cleaning up a campaign that never created artifacts must return 0."""
        from ares.core.security import cleanup_credential_artifacts
        assert cleanup_credential_artifacts("never-existed") == 0

    def test_cleanup_already_deleted_file(self):
        """If file was manually deleted before cleanup, cleanup must not crash."""
        from ares.core.security import secure_mkstemp, cleanup_credential_artifacts
        self._reset_tracking()

        p, fd = secure_mkstemp(suffix=".test", campaign_id="preempt-test")
        os.close(fd)

        # Simulate operator or other process deleted it first
        os.unlink(p)
        assert not os.path.exists(p)

        # Cleanup must succeed without error
        cleaned = cleanup_credential_artifacts("preempt-test")
        assert cleaned == 0  # file was already gone


class TestLongRunningAccumulation:
    """Prove no artifact accumulation in 24/7 operation."""

    def _reset_tracking(self):
        from ares.core.security import _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK
        with _ARTIFACT_LOCK:
            _CREDENTIAL_ARTIFACTS.clear()

    def test_long_running_no_artifact_accumulation(self):
        """
        Simulate 20 campaigns running sequentially (24/7 scenario).
        After each campaign cleanup, tracking dict must be empty for that campaign.
        No accumulation.
        """
        from ares.core.security import (
            secure_mkstemp, secure_mkdtemp, cleanup_credential_artifacts,
            _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK,
        )
        self._reset_tracking()

        for run in range(20):
            campaign_id = f"campaign-{run:04d}"

            # Each campaign creates 3 artifacts
            paths = []
            for i in range(3):
                p, fd = secure_mkstemp(
                    suffix=".ccache", prefix=f"run{run}_",
                    campaign_id=campaign_id,
                )
                os.close(fd)
                paths.append(p)

            # Verify artifacts exist
            for p in paths:
                assert os.path.exists(p)

            # Campaign cleanup
            cleaned = cleanup_credential_artifacts(campaign_id)
            assert cleaned == 3, f"Run {run}: expected 3 cleaned, got {cleaned}"

            # Verify all gone
            for p in paths:
                assert not os.path.exists(p), \
                    f"Run {run}: artifact accumulated: {p}"

            # Verify tracking dict has no entry for this campaign
            with _ARTIFACT_LOCK:
                assert campaign_id not in _CREDENTIAL_ARTIFACTS, \
                    f"Run {run}: tracking entry accumulated"

        # After 20 campaigns, tracking dict must be empty
        with _ARTIFACT_LOCK:
            assert len(_CREDENTIAL_ARTIFACTS) == 0, \
                f"CRITICAL: {len(_CREDENTIAL_ARTIFACTS)} campaigns accumulated in tracking"

    def test_concurrent_campaigns_no_interference(self):
        """
        Simulate 5 campaigns running simultaneously.
        Each cleanup must only affect its own artifacts.
        """
        from ares.core.security import (
            secure_mkstemp, cleanup_credential_artifacts,
        )
        self._reset_tracking()

        # Create artifacts for 5 campaigns
        campaign_artifacts: dict[str, list[str]] = {}
        for i in range(5):
            cid = f"concurrent-{i}"
            campaign_artifacts[cid] = []
            for j in range(2):
                p, fd = secure_mkstemp(
                    suffix=".ccache", prefix=f"conc{i}_",
                    campaign_id=cid,
                )
                os.close(fd)
                campaign_artifacts[cid].append(p)

        # All 10 artifacts exist
        all_paths = [p for paths in campaign_artifacts.values() for p in paths]
        for p in all_paths:
            assert os.path.exists(p)

        # Cleanup campaign-2 only
        cleanup_credential_artifacts("concurrent-2")

        # campaign-2 files gone
        for p in campaign_artifacts["concurrent-2"]:
            assert not os.path.exists(p)

        # Other campaigns untouched
        for cid in ["concurrent-0", "concurrent-1", "concurrent-3", "concurrent-4"]:
            for p in campaign_artifacts[cid]:
                assert os.path.exists(p), \
                    f"CRITICAL: {cid} artifact deleted by concurrent-2 cleanup: {p}"

        # Cleanup rest
        for cid in ["concurrent-0", "concurrent-1", "concurrent-3", "concurrent-4"]:
            cleanup_credential_artifacts(cid)


class TestEngineCleanupPlacement:
    """Prove engine cleanup is unconditional."""

    def test_cleanup_not_inside_pivot_block(self):
        """
        Engine cleanup_credential_artifacts call must NOT be inside
        the 'if network.pivot in results' block. It must be unconditional.
        """
        source = Path("ares/core/engine.py").read_text()
        lines = source.split("\n")

        # Find cleanup_credential_artifacts call
        cleanup_line = None
        for i, line in enumerate(lines):
            if "cleanup_credential_artifacts" in line and "import" not in line:
                cleanup_line = i
                break

        assert cleanup_line is not None, "cleanup_credential_artifacts not found in engine.py"

        # Check indentation: the cleanup call should be at the same or lower
        # indent level as the pivot if-block, NOT inside it.
        # The pivot block starts with 'if "network.pivot"' — find its indent
        pivot_line = None
        pivot_indent = None
        for i, line in enumerate(lines):
            if '"network.pivot"' in line and "if" in line:
                pivot_line = i
                pivot_indent = len(line) - len(line.lstrip())
                break

        if pivot_line is not None and cleanup_line is not None:
            cleanup_indent = len(lines[cleanup_line]) - len(lines[cleanup_line].lstrip())
            # Cleanup must NOT be more indented than the pivot if-block's body
            # (body indent = pivot_indent + 4)
            pivot_body_indent = pivot_indent + 4
            assert cleanup_indent <= pivot_body_indent, (
                f"cleanup_credential_artifacts at line {cleanup_line+1} "
                f"(indent={cleanup_indent}) is inside pivot block "
                f"(body indent={pivot_body_indent}). Must be unconditional."
            )

    def test_engine_cleanup_passes_campaign_id(self):
        """Engine must pass campaign.id to cleanup, not call without args only."""
        source = Path("ares/core/engine.py").read_text()
        assert "cleanup_credential_artifacts(campaign.id)" in source, \
            "Engine cleanup must pass campaign.id for scoped cleanup"


class TestThreadSafety:
    """Prove artifact tracking is thread-safe."""

    def _reset_tracking(self):
        from ares.core.security import _CREDENTIAL_ARTIFACTS, _ARTIFACT_LOCK
        with _ARTIFACT_LOCK:
            _CREDENTIAL_ARTIFACTS.clear()

    def test_artifact_tracking_uses_lock(self):
        """_ARTIFACT_LOCK must exist and be a lock object."""
        from ares.core.security import _ARTIFACT_LOCK
        # threading.Lock() returns _thread.lock — verify it has acquire/release
        assert hasattr(_ARTIFACT_LOCK, "acquire"), \
            "Artifact tracking must use a lock for thread safety"
        assert hasattr(_ARTIFACT_LOCK, "release"), \
            "Artifact tracking must use a lock for thread safety"

    def test_artifact_tracking_is_dict(self):
        """_CREDENTIAL_ARTIFACTS must be a dict (campaign-scoped), not a list."""
        from ares.core.security import _CREDENTIAL_ARTIFACTS
        assert isinstance(_CREDENTIAL_ARTIFACTS, dict), \
            "Artifact tracking must be dict[campaign_id, list[str]], not flat list"
