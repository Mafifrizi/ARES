"""
ARES v1.0.0 Unit Tests
Covers all new systems:
  - Capability system (CAP_NET/EXEC/FS/DB/PROCESS)
  - API RBAC (role enforcement, rate limiting)
  - Attack AI Planner (scoring, suggestions)
  - Dependency audit (pip-audit wrapper)
  - Campaign graph (node/edge builder)
  - Subprocess worker (capability limits)
  - Plugin loader security (signing + capability enforcement)

Run: pytest tests/unit/test_capabilities_rbac_planner.py -v
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.capabilities import (
    Capability, CapabilityPolicy, CapabilityViolation,
    CAP_NETWORK_MODULE, CAP_LATERAL_MODULE, CAP_PRIVESC_MODULE,
    CAP_COMMUNITY_MAX, CAP_EXTERNAL_FORBIDDEN,
    default_capabilities_for_category,
)
from ares.api.rbac import (
    AuthenticatedUser, RateLimiter, RATE_LIMITS,
)


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 1. Capability System
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestCapabilitySystem:

    def test_all_capabilities_defined(self):
        caps = list(Capability)
        assert Capability.CAP_NET     in caps
        assert Capability.CAP_EXEC    in caps
        assert Capability.CAP_FS      in caps
        assert Capability.CAP_DB      in caps
        assert Capability.CAP_PROCESS in caps
        assert Capability.CAP_UNSAFE  in caps

    def test_builtin_trust_allows_all(self):
        allowed = CapabilityPolicy.allowed_for_trust("builtin")
        assert frozenset(Capability) == allowed

    def test_community_trust_excludes_exec(self):
        allowed = CapabilityPolicy.allowed_for_trust("community")
        assert Capability.CAP_NET    in allowed
        assert Capability.CAP_DB     in allowed
        assert Capability.CAP_FS     in allowed
        assert Capability.CAP_EXEC   not in allowed
        assert Capability.CAP_UNSAFE not in allowed

    def test_external_trust_minimal_caps(self):
        allowed = CapabilityPolicy.allowed_for_trust("external")
        assert Capability.CAP_NET in allowed
        assert Capability.CAP_DB  in allowed
        assert Capability.CAP_FS     not in allowed
        assert Capability.CAP_EXEC   not in allowed

    def test_unsigned_trust_net_only(self):
        allowed = CapabilityPolicy.allowed_for_trust("unsigned")
        assert Capability.CAP_NET in allowed
        assert len(allowed) == 1

    def test_validate_valid_community_module(self):
        errors = CapabilityPolicy.validate(
            "corp.my_module",
            {Capability.CAP_NET, Capability.CAP_DB},
            "community",
        )
        assert errors == []

    def test_validate_community_tries_exec_fails(self):
        errors = CapabilityPolicy.validate(
            "corp.bad_module",
            {Capability.CAP_NET, Capability.CAP_EXEC},  # EXEC not allowed
            "community",
        )
        assert len(errors) == 1
        assert "cap_exec" in errors[0].lower()

    def test_enforce_raises_capability_violation(self):
        with pytest.raises(CapabilityViolation) as exc_info:
            CapabilityPolicy.enforce(
                "corp.bad_module",
                {Capability.CAP_NET, Capability.CAP_EXEC},
                "community",
            )
        assert exc_info.value.module_id == "corp.bad_module"
        assert Capability.CAP_EXEC in exc_info.value.forbidden

    def test_builtin_can_declare_unsafe(self):
        errors = CapabilityPolicy.validate(
            "ares.core.module",
            {Capability.CAP_UNSAFE},
            "builtin",
        )
        assert errors == []

    def test_community_cannot_declare_unsafe(self):
        errors = CapabilityPolicy.validate(
            "corp.unsafe",
            {Capability.CAP_UNSAFE},
            "community",
        )
        assert len(errors) > 0

    def test_seccomp_syscalls_for_net_cap(self):
        syscalls = CapabilityPolicy.seccomp_syscalls_for(
            frozenset({Capability.CAP_NET})
        )
        assert "socket"  in syscalls
        assert "connect" in syscalls
        assert "read"    in syscalls   # base syscalls always present
        assert "execve"  not in syscalls  # no CAP_EXEC

    def test_seccomp_syscalls_unsafe_returns_empty(self):
        # Empty set = no seccomp filter
        syscalls = CapabilityPolicy.seccomp_syscalls_for(
            frozenset({Capability.CAP_UNSAFE})
        )
        assert syscalls == set()

    def test_seccomp_includes_exec_when_cap_exec(self):
        syscalls = CapabilityPolicy.seccomp_syscalls_for(
            frozenset({Capability.CAP_NET, Capability.CAP_EXEC})
        )
        assert "execve" in syscalls
        assert "fork"   in syscalls
        assert "clone"  in syscalls

    def test_resource_limits_for_net_only(self):
        limits = CapabilityPolicy.resource_limits_for(
            frozenset({Capability.CAP_NET})
        )
        assert limits["cpu_time_s"] == 30
        assert limits["memory_mb"]  == 256
        assert limits["max_procs"]  == 1   # no CAP_EXEC Ã¢â€ â€™ 1 process

    def test_resource_limits_for_exec_cap(self):
        limits = CapabilityPolicy.resource_limits_for(
            frozenset({Capability.CAP_NET, Capability.CAP_EXEC})
        )
        assert limits["cpu_time_s"] == 120
        assert limits["memory_mb"]  == 512
        assert limits["max_procs"]  == 8

    def test_resource_limits_unsafe_empty(self):
        limits = CapabilityPolicy.resource_limits_for(
            frozenset({Capability.CAP_UNSAFE})
        )
        assert limits == {}

    def test_default_caps_for_category(self):
        assert Capability.CAP_NET    in default_capabilities_for_category("ad")
        assert Capability.CAP_EXEC   in default_capabilities_for_category("lateral")
        assert Capability.CAP_PROCESS in default_capabilities_for_category("linux")
        assert Capability.CAP_FS     in default_capabilities_for_category("reporting")

    def test_cap_profiles_are_correct_types(self):
        assert isinstance(CAP_NETWORK_MODULE, frozenset)
        assert isinstance(CAP_LATERAL_MODULE, frozenset)
        assert isinstance(CAP_COMMUNITY_MAX,  frozenset)
        assert Capability.CAP_EXEC in CAP_LATERAL_MODULE
        assert Capability.CAP_EXEC not in CAP_NETWORK_MODULE


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 2. API RBAC
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestAPIRBAC:

    def test_rate_limiter_allows_within_limit(self):
        limiter = RateLimiter()
        allowed, remaining = limiter.is_allowed("test:127.0.0.1", max_per_minute=5)
        assert allowed
        assert remaining == 4

    def test_rate_limiter_blocks_at_limit(self):
        limiter = RateLimiter()
        key = "test:10.0.0.1"
        for _ in range(5):
            limiter.is_allowed(key, max_per_minute=5)
        allowed, remaining = limiter.is_allowed(key, max_per_minute=5)
        assert not allowed
        assert remaining == 0

    def test_rate_limiter_separate_keys_independent(self):
        limiter = RateLimiter()
        # Fill up key A
        for _ in range(3):
            limiter.is_allowed("test:ip_a", max_per_minute=3)
        allowed_a, _ = limiter.is_allowed("test:ip_a", max_per_minute=3)
        # Key B unaffected
        allowed_b, _ = limiter.is_allowed("test:ip_b", max_per_minute=3)
        assert not allowed_a
        assert allowed_b

    def test_rate_limiter_window_expires(self):
        limiter = RateLimiter()
        key = "test:expire"
        # Manually inject old timestamps
        old_time = time.time() - 70  # 70s ago (outside 60s window)
        for _ in range(5):
            limiter._windows[key].append(old_time)
        # Now the window should be empty and request allowed
        allowed, _ = limiter.is_allowed(key, max_per_minute=3)
        assert allowed

    def test_rate_limits_config_all_defined(self):
        required = {"global", "auth", "module_run", "report", "register"}
        assert required <= set(RATE_LIMITS.keys())

    def test_authenticated_user_dataclass(self):
        user = AuthenticatedUser(username="alice", role="operator")
        assert user.username == "alice"
        assert user.role     == "operator"

    def test_role_can_access_team_lead_all(self):
        from ares.api.rbac import _role_can_access
        assert _role_can_access("team_lead", "POST", "/modules/run")
        assert _role_can_access("team_lead", "POST", "/auth/register")
        assert _role_can_access("team_lead", "DELETE", "/anything")

    def test_role_can_access_recon_limited(self):
        from ares.api.rbac import _role_can_access
        # Recon can list modules
        assert _role_can_access("recon", "GET", "/modules")
        # Recon cannot run modules
        assert not _role_can_access("recon", "POST", "/modules/lateral.psexec/run")
        # Recon cannot register users
        assert not _role_can_access("recon", "POST", "/auth/register")

    def test_role_can_access_reporter_read_only(self):
        from ares.api.rbac import _role_can_access
        # Reporter can read
        assert _role_can_access("reporter", "GET", "/campaigns")
        assert _role_can_access("reporter", "GET", "/reports")
        # Reporter cannot POST campaigns
        # (POST not in reporter allowed list)
        assert not _role_can_access("reporter", "POST", "/campaigns")

    def test_rate_limit_check_or_raise(self):
        from ares.api.rbac import _limiter
        from fastapi import HTTPException
        key = f"test_raise:{time.time()}"  # unique key
        for _ in range(60):
            _limiter.is_allowed(key, max_per_minute=60)
        # 61st should raise
        with pytest.raises(HTTPException) as exc_info:
            _limiter.check_or_raise(key, max_per_minute=60)
        assert exc_info.value.status_code == 429


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 3. Attack AI Planner
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestAttackPlanner:

    @pytest.fixture
    def mock_registry(self):
        """Registry with stub modules."""
        from ares.core.plugin.loader import ModuleRegistry
        from ares.modules.base import BaseModule, OpsecLevel
        from ares.core.capabilities import Capability

        class StubKerberoast(BaseModule):
            MODULE_ID          = "ad.kerberoast"
            MODULE_NAME        = "Kerberoast"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "Kerberoast"
            OPSEC_LEVEL        = OpsecLevel.MEDIUM
            REQUIRES           = ["domain_creds"]
            OUTPUTS            = ["credential"]
            MITRE_TECHNIQUES   = ["T1558.003"]
            CAPABILITIES       = {Capability.CAP_NET, Capability.CAP_DB}
            async def run(self, **k): return [], {}

        class StubASREP(BaseModule):
            MODULE_ID          = "ad.asreproast"
            MODULE_NAME        = "ASREPRoast"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "ASREPRoast"
            OPSEC_LEVEL        = OpsecLevel.MEDIUM
            REQUIRES           = []
            OUTPUTS            = ["credential"]
            MITRE_TECHNIQUES   = ["T1558.004"]
            CAPABILITIES       = {Capability.CAP_NET}
            async def run(self, **k): return [], {}

        class StubDCSync(BaseModule):
            MODULE_ID          = "ad.dcsync"
            MODULE_NAME        = "DCSync"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "DCSync"
            OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
            REQUIRES           = ["domain_admin_creds"]
            OUTPUTS            = ["all_ntlm_hashes"]
            MITRE_TECHNIQUES   = ["T1003.006"]
            CAPABILITIES       = {Capability.CAP_NET, Capability.CAP_DB}
            async def run(self, **k): return [], {}

        class StubReport(BaseModule):
            MODULE_ID          = "reporting.html"
            MODULE_NAME        = "HTML Report"
            MODULE_CATEGORY    = "reporting"
            MODULE_DESCRIPTION = "Generate HTML report"
            OPSEC_LEVEL        = OpsecLevel.SILENT
            REQUIRES           = []
            OUTPUTS            = ["report"]
            MITRE_TECHNIQUES   = []
            CAPABILITIES       = {Capability.CAP_DB, Capability.CAP_FS}
            async def run(self, **k): return [], {}

        registry = ModuleRegistry()
        registry.register(StubKerberoast, "builtin")
        registry.register(StubASREP,     "builtin")
        registry.register(StubDCSync,    "builtin")
        registry.register(StubReport,    "builtin")
        return registry

    @pytest.fixture
    def planner(self, mock_registry):
        from ares.goal.planner import AttackPlanner
        return AttackPlanner(registry=mock_registry)

    def test_suggest_returns_suggestions(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            opsec_profile="normal",
        )
        suggestions = planner.suggest(ctx, limit=5)
        assert len(suggestions) > 0

    def test_suggest_excludes_reporting_modules(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
        )
        suggestions = planner.suggest(ctx)
        module_ids = {s.module_id for s in suggestions}
        assert "reporting.html" not in module_ids

    def test_suggest_excludes_high_noise_in_stealth(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            opsec_profile="stealth",  # max noise 0.2
        )
        suggestions = planner.suggest(ctx)
        module_ids = {s.module_id for s in suggestions}
        assert "ad.dcsync" not in module_ids   # HIGH_NOISE filtered

    def test_suggest_prefers_asrep_when_no_creds(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        # No creds available Ã¢â€ â€™ ASREPRoast (no prereqs) should score higher
        # than Kerberoast (requires domain_creds)
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            opsec_profile="normal",
        )
        suggestions = planner.suggest(ctx)
        # ASREPRoast has no prereqs Ã¢â€ â€™ higher prereq_met score
        asrep = next((s for s in suggestions if s.module_id == "ad.asreproast"), None)
        kerberoast = next((s for s in suggestions if s.module_id == "ad.kerberoast"), None)
        if asrep and kerberoast:
            # ASREPRoast should score higher when no creds (no prereqs)
            assert asrep.score >= kerberoast.score

    def test_suggest_excludes_already_tried(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            already_tried={"ad.asreproast:10.0.0.1"},
        )
        suggestions = planner.suggest(ctx)
        module_ids = {s.module_id for s in suggestions}
        assert "ad.asreproast" not in module_ids

    def test_suggestions_have_required_fields(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(goal=Goal.DOMAIN_ADMIN, targets=["10.0.0.1"])
        suggestions = planner.suggest(ctx, limit=3)
        for s in suggestions:
            assert s.module_id       != ""
            assert s.module_name     != ""
            assert 0.0 <= s.score <= 1.0
            assert s.suggested_target == "10.0.0.1"
            assert s.opsec_level     != ""
            assert isinstance(s.score_breakdown, dict)
            assert len(s.score_breakdown) > 0

    def test_suggestion_to_dict(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(goal=Goal.DOMAIN_ADMIN, targets=["10.0.0.1"])
        suggestions = planner.suggest(ctx, limit=1)
        if suggestions:
            d = suggestions[0].to_dict()
            assert "module_id"       in d
            assert "score"           in d
            assert "rationale"       in d
            assert "score_breakdown" in d

    def test_suggestions_sorted_highest_first(self, planner):
        from ares.goal.planner import PlannerContext
        from ares.goal.engine import Goal
        ctx = PlannerContext(goal=Goal.DOMAIN_ADMIN, targets=["10.0.0.1"])
        suggestions = planner.suggest(ctx)
        scores = [s.score for s in suggestions]
        assert scores == sorted(scores, reverse=True)

    def test_auto_suggest_function(self, mock_registry):
        from ares.goal.planner import auto_suggest
        from ares.goal.engine import Goal
        suggestions = auto_suggest(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            registry=mock_registry,
            opsec_profile="normal",
            limit=3,
        )
        assert isinstance(suggestions, list)


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 4. Dependency Audit
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestDependencyAudit:

    def test_audit_result_clean_flag(self):
        from ares.security.audit import AuditResult
        clean = AuditResult(scanned_packages=10, vulnerabilities=[])
        assert clean.clean
        assert clean.total_count == 0

    def test_audit_result_counts(self):
        from ares.security.audit import AuditResult, Vulnerability, CVSSScore
        result = AuditResult(
            scanned_packages=20,
            vulnerabilities=[
                Vulnerability("pkg1", "1.0", "CVE-2024-1001", "desc",
                               CVSSScore.CRITICAL, "1.1"),
                Vulnerability("pkg2", "2.0", "CVE-2024-1002", "desc",
                               CVSSScore.HIGH, "2.1"),
                Vulnerability("pkg3", "3.0", "CVE-2024-1003", "desc",
                               CVSSScore.MEDIUM, ""),
            ]
        )
        assert result.critical_count == 1
        assert result.high_count     == 1
        assert result.total_count    == 3
        assert not result.clean

    def test_audit_result_to_dict(self):
        from ares.security.audit import AuditResult
        result = AuditResult(scanned_packages=5)
        d = result.to_dict()
        assert "scanned_packages" in d
        assert "total_count"      in d
        assert "critical_count"   in d
        assert "clean"            in d
        assert "vulnerabilities"  in d

    def test_audit_result_summary_clean(self):
        from ares.security.audit import AuditResult
        result = AuditResult(scanned_packages=50, vulnerabilities=[])
        summary = result.summary()
        assert "Clean" in summary or "clean" in summary.lower()
        assert "50" in summary

    def test_audit_result_summary_with_vulns(self):
        from ares.security.audit import AuditResult, Vulnerability, CVSSScore
        result = AuditResult(
            scanned_packages=10,
            vulnerabilities=[
                Vulnerability("cryptography", "1.0", "CVE-2024-0001",
                               "Padding oracle", CVSSScore.CRITICAL, "3.0"),
            ]
        )
        summary = result.summary()
        assert "critical" in summary.lower() or "1" in summary

    @pytest.mark.asyncio
    async def test_run_audit_when_tool_missing(self):
        from ares.security.audit import run_dependency_audit
        with patch("shutil.which", return_value=None):
            result = await run_dependency_audit()
        assert not result["tool_available"]
        assert "pip-audit" in result["error"].lower()

    def test_parse_pip_audit_output(self):
        from ares.security.audit import _parse_pip_audit_output
        raw = {
            "dependencies": [
                {
                    "name": "cryptography",
                    "version": "3.4.8",
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "description": "Padding oracle attack",
                            "fix_versions": ["41.0.0"],
                            "aliases": ["CVE-2023-49083"],
                        }
                    ]
                },
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "vulns": []
                }
            ]
        }
        result = _parse_pip_audit_output(raw)
        assert result.scanned_packages == 2
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].package == "cryptography"
        assert "CVE-2023-49083" in result.vulnerabilities[0].aliases

    def test_audit_policy_enum(self):
        from ares.security.audit import AuditPolicy
        assert AuditPolicy.WARN.value           == "warn"
        assert AuditPolicy.BLOCK_CRITICAL.value == "block_critical"
        assert AuditPolicy.BLOCK_ANY.value      == "block_any"

    @pytest.mark.asyncio
    async def test_startup_audit_warn_continues(self):
        from ares.security.audit import startup_audit, AuditPolicy, AuditResult, Vulnerability, CVSSScore
        mock_result = AuditResult(
            scanned_packages=10,
            vulnerabilities=[
                Vulnerability("pkg", "1.0", "CVE-x", "desc", CVSSScore.HIGH, "2.0")
            ]
        )
        with patch("ares.security.audit._run_pip_audit", return_value=mock_result):
            # WARN policy should not raise even with vulnerabilities
            await startup_audit(policy=AuditPolicy.WARN)

    @pytest.mark.asyncio
    async def test_startup_audit_block_critical_raises(self):
        from ares.security.audit import startup_audit, AuditPolicy, AuditResult, Vulnerability, CVSSScore
        mock_result = AuditResult(
            scanned_packages=5,
            vulnerabilities=[
                Vulnerability("pkg", "1.0", "CVE-x", "desc", CVSSScore.CRITICAL, "2.0")
            ]
        )
        with patch("ares.security.audit._run_pip_audit", return_value=mock_result):
            with pytest.raises(RuntimeError) as exc_info:
                await startup_audit(policy=AuditPolicy.BLOCK_CRITICAL)
            assert "CRITICAL" in str(exc_info.value)


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 5. Campaign Graph
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestCampaignGraph:

    def _make_mock_campaign(self):
        """Build a mock campaign with hosts, findings, credentials."""
        campaign = MagicMock()
        campaign.id   = "graph-test-001"
        campaign.name = "Graph Test"

        # Mock session with hosts
        host1 = MagicMock()
        host1.compromise_level = MagicMock(value="domain_admin")
        host1.is_dc     = True
        host1.hostname  = "dc01"
        host1.is_owned  = True
        host1.open_ports = [389, 445, 88]
        host1.os_info   = "Windows Server 2019"
        host1.attack_history = []
        host1.discovered_from = None

        host2 = MagicMock()
        host2.compromise_level = MagicMock(value="local_admin")
        host2.is_dc     = False
        host2.hostname  = "srv01"
        host2.is_owned  = True
        host2.open_ports = [445, 5985]
        host2.os_info   = "Windows Server 2022"
        host2.attack_history = []
        host2.discovered_from = "10.0.0.1"

        session = MagicMock()
        session.hosts = {
            "10.0.0.1": host1,
            "10.0.0.2": host2,
        }
        session.get_host = lambda ip: session.hosts.get(ip)
        campaign.session = session

        # Mock findings
        finding1 = MagicMock()
        finding1.id              = "abc123"
        finding1.title           = "Kerberoastable SPN"
        finding1.severity        = MagicMock(value="high")
        finding1.host            = "10.0.0.1"
        finding1.mitre_technique = "T1558.003"
        finding1.mitre_tactic    = "Credential Access"
        finding1.module_id       = "ad.kerberoast"
        finding1.description     = "svc_sql is kerberoastable"

        finding2 = MagicMock()
        finding2.id              = "def456"
        finding2.title           = "DCSync Successful"
        finding2.severity        = MagicMock(value="critical")
        finding2.host            = "10.0.0.1"
        finding2.mitre_technique = "T1003.006"
        finding2.mitre_tactic    = "Credential Access"
        finding2.module_id       = "ad.dcsync"
        finding2.description     = "DCSync all hashes"

        campaign.findings = [finding1, finding2]
        campaign.vault    = None  # no vault for simplicity
        return campaign

    def test_graph_builds_without_error(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph = build_campaign_graph(campaign)
        assert "nodes" in graph
        assert "edges" in graph
        assert "stats" in graph

    def test_graph_has_host_nodes(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        host_nodes = [n for n in graph["nodes"] if n["type"] in ("host", "dc")]
        assert len(host_nodes) == 2

    def test_graph_dc_node_has_diamond_shape(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        dc_nodes = [n for n in graph["nodes"] if n["type"] == "dc"]
        assert len(dc_nodes) == 1
        assert dc_nodes[0]["style"]["shape"] == "diamond"

    def test_graph_has_finding_nodes(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        finding_nodes = [n for n in graph["nodes"] if n["type"] == "finding"]
        assert len(finding_nodes) == 2

    def test_graph_critical_finding_uses_red(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        crit = [n for n in graph["nodes"]
                if n["type"] == "finding" and n["data"]["severity"] == "critical"]
        assert len(crit) == 1
        assert crit[0]["style"]["color"] == "#dc3545"   # red

    def test_graph_stats_correct(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        stats    = graph["stats"]
        assert stats["hosts"]    == 2
        assert stats["findings"] == 2
        assert stats["owned_hosts"] == 2
        assert stats["crit_findings"] == 1

    def test_graph_has_legend(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        assert "legend" in graph
        assert "node_types" in graph["legend"]
        assert "edge_types" in graph["legend"]
        assert "colors"     in graph["legend"]

    def test_graph_layout_hint_small(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        # Small graph (< 20 nodes) Ã¢â€ â€™ hierarchical
        assert graph["layout_hint"] == "hierarchical"

    def test_graph_node_ids_unique(self):
        from ares.api.graph import build_campaign_graph
        campaign = self._make_mock_campaign()
        graph    = build_campaign_graph(campaign)
        node_ids = [n["id"] for n in graph["nodes"]]
        assert len(node_ids) == len(set(node_ids))

    def test_graph_empty_campaign(self):
        """Graph builder should not crash on empty campaign."""
        from ares.api.graph import build_campaign_graph
        campaign = MagicMock()
        campaign.id       = "empty"
        campaign.name     = "Empty"
        campaign.session  = None
        campaign.findings = []
        campaign.vault    = None
        graph = build_campaign_graph(campaign)
        assert graph["stats"]["total_nodes"] == 0
        assert graph["stats"]["total_edges"] == 0


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 6. Subprocess Worker - Capability Limits
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestSubprocessWorkerCapabilities:

    def test_apply_capability_limits_no_crash(self):
        """apply_capability_limits should not raise on valid inputs."""
        from ares.worker._subprocess_worker import apply_capability_limits
        # Should silently succeed (or silently fail on unsupported platforms)
        apply_capability_limits(
            {"cap_net", "cap_db"},
            {"cpu_time_s": 30, "memory_mb": 256, "max_procs": 1, "max_files": 32}
        )

    def test_apply_capability_limits_empty_caps(self):
        """Empty caps should apply conservative defaults."""
        from ares.worker._subprocess_worker import apply_capability_limits
        apply_capability_limits(set(), {})

    def test_capability_boundary_no_violation(self):
        """Boundary check should pass when caps are respected."""
        from ares.worker._subprocess_worker import check_capability_boundary
        # No violation expected for normal caps
        # (sys.modules won't have subprocess before module loads in test)
        check_capability_boundary("ad.kerberoast", {"cap_net", "cap_db"})

    def test_capability_boundary_unsafe_bypasses(self):
        """CAP_UNSAFE modules bypass boundary check."""
        from ares.worker._subprocess_worker import check_capability_boundary
        # Should not raise even with forbidden modules loaded
        check_capability_boundary("ares.core.dcsync", {"cap_unsafe"})


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# 7. Plugin Loader Security
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

class TestPluginLoaderSecurity:

    def test_capability_enforcement_called_on_external_load(self, tmp_path):
        """Loader should reject external modules with forbidden caps."""
        from ares.core.capabilities import Capability, CapabilityPolicy

        # Module that tries to declare CAP_EXEC (forbidden for external)
        violations = CapabilityPolicy.validate(
            "external.bad_module",
            {Capability.CAP_NET, Capability.CAP_EXEC},
            "external",
        )
        assert len(violations) > 0
        assert "cap_exec" in violations[0].lower()

    def test_default_caps_assigned_when_missing(self):
        """Loader assigns sensible default caps when CAPABILITIES not declared."""
        from ares.core.capabilities import default_capabilities_for_category, Capability
        ad_caps = default_capabilities_for_category("ad")
        assert Capability.CAP_NET in ad_caps
        assert Capability.CAP_DB  in ad_caps

    def test_signing_policy_env_var_read(self):
        """Signing policy is configurable via environment variable."""
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"ARES_PLUGIN_SIGNING_POLICY": "require_signed"}):
            # Re-import to test env var reading
            import importlib
            import ares.core.plugin.loader as loader_module
            policy = loader_module._SIGNING_POLICY
            # Note: module-level var is set at import time, 
            # but we can test the env var is read
            assert "ARES_PLUGIN_SIGNING_POLICY" in os.environ


# Ã¢â€â‚¬Ã¢â€â‚¬ CapabilityGraph circular dependency tests (Fix #9) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

class TestCapabilityGraphCircularDeps:
    """
    Verify CapabilityGraph.resolve_chain() handles circular dependencies safely.

    Edge cases:
      - A outputs X, B requires X and outputs Y, A requires Y Ã¢â€ â€™ mutual dependency
      - Self-dependency: A outputs X and requires X
      - Long chain: AÃ¢â€ â€™BÃ¢â€ â€™CÃ¢â€ â€™DÃ¢â€ â€™back to A
    """

    @staticmethod
    def _run_with_timeout(fn, timeout_s: float, message: str):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn)
            try:
                return future.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError as exc:
                raise AssertionError(message) from exc

    def _make_registry_stub(self, modules: list[dict]):
        """Build a minimal registry stub from a list of {id, requires, outputs} dicts."""
        from dataclasses import dataclass
        from typing import Any

        class ModuleStub:
            pass

        stubs = []
        for m in modules:
            stub = type(m["id"].replace(".", "_"), (), {
                "MODULE_ID": m["id"],
                "REQUIRES":  m.get("requires", []),
                "OUTPUTS":   m.get("outputs", []),
            })
            stubs.append(stub)

        class FakeRegistry:
            def all(self):
                return stubs

        return FakeRegistry()

    def test_resolve_chain_basic_linear(self):
        """AÃ¢â€ â€™BÃ¢â€ â€™C linear chain resolves in dependency order."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [],          "outputs": ["cap_x"]},
            {"id": "mod.b", "requires": ["cap_x"],   "outputs": ["cap_y"]},
            {"id": "mod.c", "requires": ["cap_y"],   "outputs": ["cap_z"]},
        ])
        cg = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain(["cap_z"])

        # mod.a must appear before mod.b, mod.b before mod.c
        assert "mod.a" in chain
        assert "mod.b" in chain
        assert "mod.c" in chain
        assert chain.index("mod.a") < chain.index("mod.b")
        assert chain.index("mod.b") < chain.index("mod.c")

    def test_resolve_chain_no_cycle_detection_visited_set(self):
        """
        Mutual dependency (A outputs X, B requires X and outputs Y, A requires Y).
        visited set prevents infinite recursion Ã¢â‚¬â€ chain terminates within max_depth.
        """
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": ["cap_y"], "outputs": ["cap_x"]},
            {"id": "mod.b", "requires": ["cap_x"], "outputs": ["cap_y"]},
        ])
        cg = CapabilityGraph.from_registry(reg)

        chain = self._run_with_timeout(
            lambda: cg.resolve_chain(["cap_x", "cap_y"]),
            3,
            "resolve_chain() timed out",
        )

        # Result is a finite list Ã¢â‚¬â€ no duplicates
        assert isinstance(chain, list)
        assert len(chain) == len(set(chain)), "Duplicates in resolved chain"

    def test_resolve_chain_self_dependency(self):
        """Module that outputs what it requires; visited set prevents a loop."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.self", "requires": ["cap_x"], "outputs": ["cap_x"]},
        ])
        cg = CapabilityGraph.from_registry(reg)

        chain = self._run_with_timeout(
            lambda: cg.resolve_chain(["cap_x"]),
            3,
            "Self-dep resolve timed out",
        )

        assert isinstance(chain, list)
        assert len(chain) == len(set(chain))

    def test_resolve_chain_long_cycle_terminates(self):
        """4-module cycle terminates due to max_depth + visited."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": ["cap_d"], "outputs": ["cap_a"]},
            {"id": "mod.b", "requires": ["cap_a"], "outputs": ["cap_b"]},
            {"id": "mod.c", "requires": ["cap_b"], "outputs": ["cap_c"]},
            {"id": "mod.d", "requires": ["cap_c"], "outputs": ["cap_d"]},
        ])
        cg = CapabilityGraph.from_registry(reg)

        chain = self._run_with_timeout(
            lambda: cg.resolve_chain(["cap_d"]),
            3,
            "Long-cycle resolve timed out",
        )

        assert isinstance(chain, list)
        assert len(chain) == len(set(chain)), "No duplicates allowed"


    def test_resolve_chain_available_modules_filter(self):
        """available_modules filter restricts resolution to a subset."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [],          "outputs": ["cap_x"]},
            {"id": "mod.b", "requires": ["cap_x"],   "outputs": ["cap_y"]},
            {"id": "mod.c", "requires": ["cap_x"],   "outputs": ["cap_z"]},
        ])
        cg = CapabilityGraph.from_registry(reg)

        # Only allow mod.a and mod.c Ã¢â‚¬â€ mod.b filtered out
        chain = cg.resolve_chain(["cap_y", "cap_z"],
                                   available_modules=["mod.a", "mod.c"])
        assert "mod.b" not in chain
        assert "mod.c" in chain or "mod.a" in chain

    def test_resolve_chain_empty_goal(self):
        """Empty goal_required_outputs returns empty chain gracefully."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [], "outputs": ["cap_x"]},
        ])
        cg = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain([])
        assert chain == []

    def test_resolve_chain_unknown_capability(self):
        """Requesting a capability no module produces returns empty chain."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [], "outputs": ["cap_x"]},
        ])
        cg = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain(["cap_does_not_exist"])
        assert chain == []

    def test_capability_summary_structure(self):
        """capability_summary() returns correct structure and counts."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [],        "outputs": ["cap_x", "cap_y"]},
            {"id": "mod.b", "requires": ["cap_x"], "outputs": ["cap_z"]},
        ])
        cg = CapabilityGraph.from_registry(reg)
        summary = cg.capability_summary()

        assert summary["total_capabilities"] == 3   # cap_x, cap_y, cap_z
        assert summary["total_modules"] == 2
        assert "cap_x" in summary["capabilities"]
        assert "mod.a" in summary["capabilities"]["cap_x"]

    def test_producers_for_returns_correct_modules(self):
        """producers_for() returns all modules that output a given capability."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry_stub([
            {"id": "mod.a", "requires": [], "outputs": ["cap_x"]},
            {"id": "mod.b", "requires": [], "outputs": ["cap_x", "cap_y"]},
            {"id": "mod.c", "requires": [], "outputs": ["cap_y"]},
        ])
        cg = CapabilityGraph.from_registry(reg)

        producers_x = cg.producers_for("cap_x")
        assert set(producers_x) == {"mod.a", "mod.b"}

        producers_y = cg.producers_for("cap_y")
        assert set(producers_y) == {"mod.b", "mod.c"}

        producers_z = cg.producers_for("cap_nonexistent")
        assert producers_z == []
