"""
Unit tests — AdaptiveOpsecEngine (ares/core/opsec/adaptive.py)

Every detection signal type and every response action is tested.
Also tests thresholds, sliding window, blacklist expiry, and edge cases.
"""
from __future__ import annotations

import time
import pytest
from unittest.mock import patch

from ares.core.opsec.adaptive import (
    AdaptiveOpsecEngine,
    DetectionLevel,
    ResponseAction,
    SignalEvent,
    OpsecAdaptation,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_engine(**kwargs) -> AdaptiveOpsecEngine:
    defaults = dict(
        current_profile="normal",
        window_s=60.0,
        timeout_threshold=3,
        reset_threshold=5,
        auth_fail_threshold=3,
        jitter_increment_s=2.0,
    )
    defaults.update(kwargs)
    return AdaptiveOpsecEngine(**defaults)


# ══════════════════════════════════════════════════════════════════════════════
# Signal registration
# ══════════════════════════════════════════════════════════════════════════════

class TestSignalRegistration:

    def test_signal_stores_event(self):
        engine = make_engine()
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert len(engine._signals[DetectionLevel.TIMEOUT.value]) == 1

    def test_signal_increments_host_counter(self):
        engine = make_engine()
        engine.signal(DetectionLevel.CONNECTION_RESET, host="10.0.0.5")
        engine.signal(DetectionLevel.CONNECTION_RESET, host="10.0.0.5")
        assert engine._host_failures["10.0.0.5"] == 2

    def test_signal_increments_account_counter(self):
        engine = make_engine()
        engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="jdoe")
        engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="JDOE")
        # Case-insensitive
        assert engine._account_failures["jdoe"] == 2

    def test_signal_returns_empty_list_below_threshold(self):
        engine = make_engine(timeout_threshold=3)
        result = engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        # Only 1 timeout, threshold is 3 — no adaptations yet
        assert result == []

    def test_multiple_signal_types(self):
        engine = make_engine()
        for sig in DetectionLevel:
            engine.signal(sig, host="10.0.0.1", username="test")
        # No assertion on count — just verify no crash


# ══════════════════════════════════════════════════════════════════════════════
# Timeout rule
# ══════════════════════════════════════════════════════════════════════════════

class TestTimeoutRule:

    def test_escalates_profile_at_threshold(self):
        engine = make_engine(timeout_threshold=3, current_profile="normal")
        for _ in range(3):
            adaptations = engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert any(a.action == ResponseAction.ESCALATE_PROFILE for a in adaptations)

    def test_new_profile_is_stealth_from_normal(self):
        engine = make_engine(timeout_threshold=1, current_profile="normal")
        adaptations = engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert any(a.new_profile == "stealth" for a in adaptations)

    def test_stealth_stays_stealth(self):
        engine = make_engine(timeout_threshold=1, current_profile="stealth")
        adaptations = engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        escalations = [a for a in adaptations if a.action == ResponseAction.ESCALATE_PROFILE]
        if escalations:
            # stealth is already max — stays stealth
            assert escalations[0].new_profile == "stealth"

    def test_jitter_increases_with_timeout(self):
        engine = make_engine(timeout_threshold=2, jitter_increment_s=3.0)
        for _ in range(2):
            engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert engine._current_jitter_boost > 0.0

    def test_effective_profile_changes_after_timeout_escalation(self):
        engine = make_engine(timeout_threshold=1, current_profile="aggressive")
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert engine.effective_profile() != "aggressive"

    def test_window_resets_old_signals(self):
        """Signals older than window_s must not count toward threshold."""
        engine = make_engine(timeout_threshold=2, window_s=0.1)
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        time.sleep(0.2)  # let them expire
        # New signal — count should be 1, below threshold 2
        adaptations = engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert not any(a.action == ResponseAction.ESCALATE_PROFILE for a in adaptations)


# ══════════════════════════════════════════════════════════════════════════════
# Connection reset / blacklist rule
# ══════════════════════════════════════════════════════════════════════════════

class TestConnectionResetRule:

    def test_blacklists_host_at_threshold(self):
        engine = make_engine(reset_threshold=5)
        for _ in range(5):
            adaptations = engine.signal(DetectionLevel.CONNECTION_RESET, host="192.168.1.10")
        assert any(a.action == ResponseAction.BLACKLIST_HOST for a in adaptations)
        assert engine.is_host_blacklisted("192.168.1.10")

    def test_blacklist_does_not_affect_other_hosts(self):
        engine = make_engine(reset_threshold=3)
        for _ in range(3):
            engine.signal(DetectionLevel.CONNECTION_RESET, host="10.0.0.1")
        assert not engine.is_host_blacklisted("10.0.0.2")

    def test_blacklist_expires(self):
        engine = make_engine(reset_threshold=1)
        engine.signal(DetectionLevel.CONNECTION_RESET, host="10.0.0.99")
        # Manually expire it
        engine._blacklisted_hosts["10.0.0.99"] = time.monotonic() - 1
        assert not engine.is_host_blacklisted("10.0.0.99")
        # Also verify cleanup removes it
        assert "10.0.0.99" not in engine._blacklisted_hosts

    def test_non_reset_signal_does_not_trigger_blacklist(self):
        engine = make_engine(reset_threshold=3)
        for _ in range(5):
            engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert not engine.is_host_blacklisted("10.0.0.1")


# ══════════════════════════════════════════════════════════════════════════════
# Auth failure / lockout protection rule
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthFailureRule:

    def test_stops_account_at_threshold(self):
        engine = make_engine(auth_fail_threshold=3)
        for _ in range(3):
            adaptations = engine.signal(
                DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="svc_acct"
            )
        assert any(a.action == ResponseAction.STOP_ACCOUNT for a in adaptations)
        assert engine.is_account_stopped("svc_acct")

    def test_case_insensitive_account_stop(self):
        engine = make_engine(auth_fail_threshold=2)
        engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="Admin")
        engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="ADMIN")
        assert engine.is_account_stopped("admin")

    def test_failed_login_also_triggers_stop(self):
        engine = make_engine(auth_fail_threshold=2)
        for _ in range(2):
            engine.signal(DetectionLevel.FAILED_LOGIN, host="10.0.0.1", username="bob")
        assert engine.is_account_stopped("bob")

    def test_no_username_does_not_crash(self):
        engine = make_engine()
        adaptations = engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1")
        # No username → no account stop, no crash
        assert not any(a.action == ResponseAction.STOP_ACCOUNT for a in adaptations)

    def test_different_accounts_tracked_independently(self):
        engine = make_engine(auth_fail_threshold=3)
        for _ in range(3):
            engine.signal(DetectionLevel.AUTH_FAILURE, host="10.0.0.1", username="alice")
        assert engine.is_account_stopped("alice")
        assert not engine.is_account_stopped("bob")


# ══════════════════════════════════════════════════════════════════════════════
# Rate limited rule
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimitedRule:

    def test_increases_jitter_on_rate_limit(self):
        engine = make_engine(jitter_increment_s=5.0)
        boost_before = engine.current_jitter_boost()
        engine.signal(DetectionLevel.RATE_LIMITED, host="10.0.0.1")
        assert engine.current_jitter_boost() > boost_before

    def test_jitter_doubles_on_rate_limit(self):
        """Rate limit uses 2× jitter_increment."""
        engine = make_engine(jitter_increment_s=2.0)
        engine.signal(DetectionLevel.RATE_LIMITED, host="10.0.0.1")
        # First hit: 0 + 2*2 = 4
        assert engine.current_jitter_boost() == 4.0

    def test_rate_limited_always_triggers(self):
        """Every RATE_LIMITED signal triggers INCREASE_JITTER regardless of count."""
        engine = make_engine()
        for i in range(5):
            adaptations = engine.signal(DetectionLevel.RATE_LIMITED, host="10.0.0.1")
            assert any(a.action == ResponseAction.INCREASE_JITTER for a in adaptations)


# ══════════════════════════════════════════════════════════════════════════════
# Scan detected rule
# ══════════════════════════════════════════════════════════════════════════════

class TestScanDetectedRule:

    def test_pause_all_on_scan_detected(self):
        engine = make_engine()
        adaptations = engine.signal(DetectionLevel.SCAN_DETECTED, host="10.0.0.1")
        assert any(a.action == ResponseAction.PAUSE_ALL for a in adaptations)
        assert engine.is_paused()

    def test_profile_becomes_stealth_on_scan(self):
        engine = make_engine(current_profile="aggressive")
        engine.signal(DetectionLevel.SCAN_DETECTED, host="10.0.0.1")
        assert engine.current_profile == "stealth"

    def test_resume_unpauses(self):
        engine = make_engine()
        engine.signal(DetectionLevel.SCAN_DETECTED, host="10.0.0.1")
        assert engine.is_paused()
        engine.resume()
        assert not engine.is_paused()


# ══════════════════════════════════════════════════════════════════════════════
# Adaptation tracking & summary
# ══════════════════════════════════════════════════════════════════════════════

class TestAdaptationTracking:

    def test_adaptations_list_grows(self):
        engine = make_engine(timeout_threshold=1)
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        assert len(engine.adaptations) >= 1

    def test_summary_returns_complete_dict(self):
        engine = make_engine()
        summary = engine.summary()
        assert "current_profile" in summary
        assert "jitter_boost_s" in summary
        assert "paused" in summary
        assert "blacklisted_hosts" in summary
        assert "stopped_accounts" in summary
        assert "total_adaptations" in summary
        assert "recent_signals" in summary

    def test_summary_signal_counts(self):
        engine = make_engine()
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.2")
        summary = engine.summary()
        assert summary["recent_signals"][DetectionLevel.TIMEOUT.value] == 2

    def test_profile_order_correct(self):
        assert AdaptiveOpsecEngine.NOISE_PROFILE_ORDER == ["aggressive", "normal", "stealth"]

    def test_next_stealth_profile_from_aggressive(self):
        engine = make_engine(current_profile="aggressive")
        assert engine._next_stealth_profile() == "normal"

    def test_next_stealth_profile_from_normal(self):
        engine = make_engine(current_profile="normal")
        assert engine._next_stealth_profile() == "stealth"

    def test_next_stealth_profile_from_stealth(self):
        engine = make_engine(current_profile="stealth")
        # Already at max — stays stealth
        assert engine._next_stealth_profile() == "stealth"


# ══════════════════════════════════════════════════════════════════════════════
# Edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_empty_host_does_not_crash(self):
        engine = make_engine()
        engine.signal(DetectionLevel.TIMEOUT, host="")
        # No crash

    def test_multiple_signals_same_host_different_types(self):
        engine = make_engine(timeout_threshold=1, reset_threshold=1)
        engine.signal(DetectionLevel.TIMEOUT, host="10.0.0.1")
        engine.signal(DetectionLevel.CONNECTION_RESET, host="10.0.0.1")
        # Both rules should fire independently
        assert engine.is_host_blacklisted("10.0.0.1")
        assert engine.current_profile == "stealth"

    def test_unknown_profile_falls_back_gracefully(self):
        engine = make_engine(current_profile="unknown_profile")
        result = engine._next_stealth_profile()
        assert result in AdaptiveOpsecEngine.NOISE_PROFILE_ORDER

    def test_cert_error_and_unexpected_close_registered(self):
        """These signals must be registerable without crashing."""
        engine = make_engine()
        engine.signal(DetectionLevel.CERT_ERROR, host="10.0.0.1")
        engine.signal(DetectionLevel.UNEXPECTED_CLOSE, host="10.0.0.1")
        assert len(engine._signals[DetectionLevel.CERT_ERROR.value]) == 1
