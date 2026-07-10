"""
ARES Security Critical Path Tests
==================================
Test suite for security-critical paths that must pass before every release.

Coverage:
    1. Token revocation  — logout → blacklist → reuse rejected
    2. Dashboard auth    — every API endpoint requires valid token
    3. RBAC enforcement  — per-role, per-endpoint access control
    4. Refresh rate limit — 429 after N rapid refresh attempts
    5. Vault persistence  — save/restore credential cycle
    6. validate() enforcement — engine calls validate() before execute()

Pattern: httpx.ASGITransport + dependency_overrides (no lifespan needed).
All tests are self-contained — no shared mutable state between classes.
"""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock

# ── env bootstrap (before any ares import) ────────────────────────────────────
os.environ.setdefault("ARES_SECRET_KEY",             "test-sec-critical-min32-chars!!!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",         "test-enc-critical-min32-chars!!!!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestCriticalPass1!")


# ── helpers ───────────────────────────────────────────────────────────────────

def _settings():
    from ares.core.config import get_settings
    get_settings.cache_clear()
    return get_settings()


def _make_token(username: str, role: str, expires_minutes: int = 60) -> str:
    from ares.core.security import create_access_token
    s = _settings()
    return create_access_token(
        data={"sub": username, "role": role},
        secret_key=s.secret_key_value,
        expires_minutes=expires_minutes,
    )


def _auth(username: str, role: str) -> dict:
    return {"Authorization": f"Bearer {_make_token(username, role)}"}


def _make_mock_db():
    db = MagicMock()
    db.verify_user               = AsyncMock(return_value=None)
    db.get_user                  = AsyncMock(return_value=None)
    db.user_exists               = AsyncMock(return_value=False)
    db.create_user               = AsyncMock()
    db.create_refresh_token      = AsyncMock(return_value="raw-mock-refresh-token")
    db.rotate_refresh_token      = AsyncMock(return_value=(None, None))
    db.revoke_all_refresh_tokens = AsyncMock()
    db.revoke_access_token       = AsyncMock()
    db.is_access_token_revoked   = AsyncMock(return_value=False)
    db.audit                     = AsyncMock()
    db.purge_expired_tokens      = AsyncMock(return_value=0)
    db.list_campaigns            = AsyncMock(return_value=([], 0))
    db.get_campaign              = AsyncMock(return_value=None)
    db.verify_api_key            = AsyncMock(return_value=None)
    db.load_credentials_raw      = AsyncMock(return_value=[])
    return db


def _reset_limiter() -> None:
    from ares.api.rbac import _limiter
    _limiter._windows.clear()


def _run(coro):
    return asyncio.run(coro)


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 1 — TOKEN REVOCATION
# ══════════════════════════════════════════════════════════════════════

class TestTokenRevocation:
    """
    After logout, a still-valid (not-expired) access token must be rejected.
    The JTI blacklist is the mechanism — these tests verify it is enforced.
    """

    def setup_method(self):
        _reset_limiter()

    def _client(self, mock_db):
        import httpx
        from ares.api.server import app, get_db, get_settings
        app.state.db = mock_db
        app.dependency_overrides[get_db]       = lambda: mock_db
        app.dependency_overrides[get_settings] = lambda: _settings()
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
        )

    def test_revoked_token_rejected(self):
        """Token whose JTI is in the blacklist must return 401."""
        db = _make_mock_db()
        db.is_access_token_revoked = AsyncMock(return_value=True)  # blacklisted

        async def _run_test():
            async with self._client(db) as c:
                r = await c.get("/auth/me", headers=_auth("alice", "operator"))
            assert r.status_code == 401, (
                f"Revoked token must return 401, got {r.status_code}. "
                "Logout is ineffective — token still works after revocation!"
            )
        _run(_run_test())

    def test_valid_token_accepted(self):
        """Token not in blacklist must work normally."""
        db = _make_mock_db()
        db.is_access_token_revoked = AsyncMock(return_value=False)
        db.get_user = AsyncMock(return_value={
            "id": "u1", "username": "alice", "role": "operator"
        })

        async def _run_test():
            async with self._client(db) as c:
                r = await c.get("/auth/me", headers=_auth("alice", "operator"))
            assert r.status_code == 200, (
                f"Valid token must return 200, got {r.status_code}"
            )
        _run(_run_test())

    def test_expired_token_rejected(self):
        """JWT past its exp claim must return 401."""
        db = _make_mock_db()
        token = _make_token("alice", "operator", expires_minutes=-1)

        async def _run_test():
            async with self._client(db) as c:
                r = await c.get("/auth/me",
                                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401, (
                f"Expired token must return 401, got {r.status_code}"
            )
        _run(_run_test())

    def test_logout_triggers_revocation(self):
        """POST /auth/logout must call DB revocation methods."""
        db = _make_mock_db()
        db.is_access_token_revoked = AsyncMock(return_value=False)
        db.get_user = AsyncMock(return_value={
            "id": "u1", "username": "alice", "role": "operator"
        })

        async def _run_test():
            async with self._client(db) as c:
                r = await c.post("/auth/logout", headers=_auth("alice", "operator"))
            assert r.status_code == 200
            db.revoke_all_refresh_tokens.assert_called_once()
        _run(_run_test())


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 2 — DASHBOARD AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════

class TestDashboardAuthentication:
    """
    Every dashboard /api/* endpoint must return 401 without a valid token.
    GET / (HTML shell) is deliberately public — SPA pattern, no sensitive data.
    """

    PROTECTED = [
        ("GET",  "/api/status"),
        ("GET",  "/api/campaigns"),
        ("GET",  "/api/campaigns/test-id/findings"),
        ("GET",  "/api/campaigns/test-id/hosts"),
        ("GET",  "/api/campaigns/test-id/summary"),
        ("GET",  "/api/workers"),
    ]

    def _client(self):
        import httpx
        from ares.api.dashboard.app import dashboard_app
        dashboard_app.state.db = _make_mock_db()
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app),
            base_url="http://localhost",
        )

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_endpoint_requires_auth(self, method, path):
        """Each protected endpoint must return 401 with no token."""
        async def _run_test():
            async with self._client() as c:
                r = await c.request(method, path)
            assert r.status_code == 401, (
                f"Dashboard [{method}] {path} returned {r.status_code} without auth. "
                "This endpoint exposes campaign data without authentication!"
            )
        _run(_run_test())

    def test_root_accessible_without_auth(self):
        """GET / (HTML shell) is intentionally public."""
        async def _run_test():
            async with self._client() as c:
                r = await c.get("/")
            assert r.status_code == 200
        _run(_run_test())

    def test_valid_token_grants_access(self):
        """A valid JWT must give access to /api/campaigns."""
        db = _make_mock_db()
        db.list_campaigns = AsyncMock(return_value=([], 0))

        async def _run_test():
            import httpx
            from ares.api.dashboard.app import dashboard_app
            db.is_access_token_revoked = AsyncMock(return_value=False)
            dashboard_app.state.db = db
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=dashboard_app),
                base_url="http://localhost",
            ) as c:
                r = await c.get("/api/campaigns",
                                headers=_auth("alice", "operator"))
            assert r.status_code == 200
        _run(_run_test())


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 3 — RBAC ENFORCEMENT PER ROLE
# ══════════════════════════════════════════════════════════════════════

def test_legacy_dashboard_escapes_api_fields_before_innerhtml():
    """API-derived strings must be escaped before legacy dashboard innerHTML use."""
    from ares.api.dashboard.app import _DASHBOARD_HTML

    escaped_fragments = [
        "${escHtml(c.id)}",
        "${escHtml(c.name)}",
        "${escHtml(c.client)}",
        "${escHtml(c.noise_profile)}",
        "${escHtml(c.status)}",
        "${escHtml(String(f.severity || 'info').toUpperCase())}",
        "${escHtml(f.mitre_technique)}",
        "${escHtml(h.ip_address)}",
        "${escHtml(h.hostname)}",
        "${escHtml(h.os || 'Unknown OS')}",
        "escHtml(h.os_version)",
        "escHtml(h.domain)",
        "JSON.parse(h.open_ports_json).map(escHtml).join(', ')",
        "${escHtml(w.hostname)}",
        "${escHtml(String(w.id || '').slice(0,8))}",
        "(w.capabilities || []).map(escHtml).join(', ')",
        "${escHtml(w.last_beat)}",
        "${escHtml(w.active_tasks)}",
        "${escHtml(w.completed)}",
        "${escHtml(w.failed)}",
    ]
    for fragment in escaped_fragments:
        assert fragment in _DASHBOARD_HTML

    vulnerable_fragments = [
        "onclick=\"selectCampaign('${c.id}', this)\"",
        "${c.name}</div>",
        "${c.client}",
        "${f.mitre_technique}</span>",
        "<span class=\"ip\">${h.ip_address}</span>",
        ">(${h.hostname})</span>",
        "${h.os || 'Unknown OS'}",
        "' ' + h.os_version",
        "JSON.parse(h.open_ports_json).join(', ')",
        "${w.hostname}</strong>",
        "${w.id.slice(0,8)}",
        "${w.capabilities.join(', ')||'all'}",
        "${w.last_beat}s ago",
        "${w.active_tasks}</strong>",
        "Done: ${w.completed}",
        "Failed: ${w.failed}",
    ]
    for fragment in vulnerable_fragments:
        assert fragment not in _DASHBOARD_HTML

    assert ".replace(/\"/g,'&quot;')" in _DASHBOARD_HTML
    assert ".replace(/'/g,'&#39;')" in _DASHBOARD_HTML


class TestRBACEnforcement:
    """
    Every role must be restricted to its allowed operations.
    """

    def setup_method(self):
        _reset_limiter()

    def _client(self, mock_db=None):
        import httpx
        from ares.api.server import app, get_db, get_settings
        db = mock_db or _make_mock_db()
        app.state.db = db
        app.dependency_overrides[get_db]       = lambda: db
        app.dependency_overrides[get_settings] = lambda: _settings()
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
        )

    def test_no_token_returns_401(self):
        """Unauthenticated request must return 401, not 403."""
        async def _run_test():
            async with self._client() as c:
                r = await c.get("/campaigns")
            assert r.status_code == 401, (
                f"No token must return 401, not {r.status_code}"
            )
        _run(_run_test())

    def test_reporter_blocked_from_creating_campaign(self):
        """Reporter (read-only) must be blocked from POST /campaigns."""
        db = _make_mock_db()

        async def _run_test():
            async with self._client(db) as c:
                r = await c.post(
                    "/campaigns",
                    json={"name": "test", "targets": [], "scope_cidrs": []},
                    headers=_auth("reporter1", "reporter"),
                )
            assert r.status_code == 403, (
                f"Reporter must get 403 on POST /campaigns, got {r.status_code}"
            )
        _run(_run_test())

    def test_reporter_can_read_campaigns(self):
        """Reporter must be able to GET /campaigns."""
        db = _make_mock_db()

        async def _run_test():
            async with self._client(db) as c:
                r = await c.get("/campaigns",
                                headers=_auth("reporter1", "reporter"))
            assert r.status_code == 200, (
                f"Reporter must be able to read campaigns, got {r.status_code}"
            )
        _run(_run_test())

    def test_operator_blocked_from_registering_users(self):
        """Only team_lead may call POST /auth/register."""
        db = _make_mock_db()

        async def _run_test():
            async with self._client(db) as c:
                r = await c.post(
                    "/auth/register",
                    json={"username": "newuser", "password": "Password1!",
                          "role": "operator"},
                    headers=_auth("op1", "operator"),
                )
            assert r.status_code == 403, (
                f"Operator must be blocked from /auth/register, got {r.status_code}"
            )
        _run(_run_test())

    def test_team_lead_can_register_users(self):
        """team_lead must be able to reach POST /auth/register."""
        db = _make_mock_db()
        db.user_exists = AsyncMock(return_value=False)
        db.create_user = AsyncMock(return_value="new-user-id")

        async def _run_test():
            async with self._client(db) as c:
                r = await c.post(
                    "/auth/register",
                    json={"username": "newuser", "password": "StrongPass1!",
                          "role": "operator"},
                    headers=_auth("lead1", "team_lead"),
                )
            assert r.status_code in (200, 201, 422), (
                f"team_lead must reach /auth/register (200/201), got {r.status_code}"
            )
        _run(_run_test())

    def test_can_run_module_rbac_operator(self):
        """operator may run ad.* and lateral.* modules."""
        from ares.api.rbac import AuthenticatedUser
        user = AuthenticatedUser(username="op1", role="operator")
        assert user.can_run_module("ad.kerberoast")
        assert user.can_run_module("lateral.psexec")
        assert user.can_run_module("windows.lsa_secrets")

    def test_can_run_module_rbac_recon(self):
        """recon may only run enumeration modules."""
        from ares.api.rbac import AuthenticatedUser
        user = AuthenticatedUser(username="recon1", role="recon")
        assert user.can_run_module("ad.enum_users")
        assert user.can_run_module("network.port_scan")
        # Must NOT run lateral or credential modules
        assert not user.can_run_module("lateral.psexec")
        assert not user.can_run_module("credential.reuse")

    def test_can_run_module_rbac_reporter(self):
        """reporter may not run any module."""
        from ares.api.rbac import AuthenticatedUser
        user = AuthenticatedUser(username="rep1", role="reporter")
        assert not user.can_run_module("ad.enum_users")
        assert not user.can_run_module("reporting.report_gen")

    def test_unknown_role_defaults_to_reporter(self):
        """Unknown role string must default to most restrictive (reporter)."""
        from ares.api.rbac import AuthenticatedUser
        from ares.collab.manager import OperatorRole
        user = AuthenticatedUser(username="mystery", role="god_mode")
        assert user.operator_role == OperatorRole.REPORTER
        assert not user.can_run_module("ad.kerberoast")


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 4 — REFRESH TOKEN RATE LIMITING
# ══════════════════════════════════════════════════════════════════════

class TestRefreshTokenRateLimit:
    """POST /auth/refresh must be rate-limited to prevent token flooding."""

    def setup_method(self):
        _reset_limiter()

    def _client(self, mock_db=None):
        import httpx
        from ares.api.server import app, get_db, get_settings
        db = mock_db or _make_mock_db()
        app.state.db = db
        app.dependency_overrides[get_db]       = lambda: db
        app.dependency_overrides[get_settings] = lambda: _settings()
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
        )

    def test_rate_limited_after_many_attempts(self):
        """After N refresh calls from same IP, 429 must be returned."""
        from ares.api.rbac import RATE_LIMITS
        limit = RATE_LIMITS["auth"]

        async def _run_test():
            async with self._client() as c:
                statuses = []
                for i in range(limit + 2):
                    r = await c.post("/auth/refresh",
                                     json={"refresh_token": f"fake-{i}"})
                    statuses.append(r.status_code)
            assert 429 in statuses, (
                f"Expected 429 after {limit} attempts, got statuses: {statuses}"
            )
        _run(_run_test())

    def test_429_has_retry_after_header(self):
        """Rate-limit 429 response must include Retry-After header."""
        from ares.api.rbac import RATE_LIMITS
        limit = RATE_LIMITS["auth"]

        async def _run_test():
            async with self._client() as c:
                for i in range(limit + 1):
                    r = await c.post("/auth/refresh",
                                     json={"refresh_token": f"fake-{i}"})
                    if r.status_code == 429:
                        headers_lower = {k.lower(): v for k, v in r.headers.items()}
                        assert "retry-after" in headers_lower, (
                            "429 response must include Retry-After header"
                        )
                        return
            pytest.fail("Never received 429 — rate limiting not working")
        _run(_run_test())


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 5 — CREDENTIAL VAULT PERSISTENCE
# ══════════════════════════════════════════════════════════════════════

class TestCredentialVaultPersistence:
    """Credentials found during a module run must persist to DB and be restorable."""

    def test_persist_vault_saves_to_db(self):
        """Engine _persist_vault_credentials() must call save_credential_preencrypted."""
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.engine import AresEngine

        db = MagicMock()
        db.save_credential_preencrypted = AsyncMock()

        campaign = Campaign(
            name="persist-test", client="test",
            scope=[ScopeEntry(cidr="10.0.0.0/8")],
            noise_profile=NoiseProfile.NORMAL,
        )
        vault = CredentialVault(encryption_key="test-vault-key-32-chars-ok!!!!")
        cred  = Credential(
            campaign_id=campaign.id,
            username="administrator",
            domain="CORP",
            cred_type=CredentialType.NTLM,
            source_module="ad.dcsync",
        )
        vault.store(cred, "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
        campaign._vault = vault  # type: ignore[attr-defined]

        engine = AresEngine(db=db)

        async def _run_test():
            saved = await engine._persist_vault_credentials(campaign)
            assert saved == 1, f"Must save 1 credential, got {saved}"
            db.save_credential_preencrypted.assert_called_once()
            call = db.save_credential_preencrypted.call_args[0][0]
            assert call.username == "administrator"
            assert call.domain   == "CORP"
            assert "ntlm" in call.cred_type.lower()
        _run(_run_test())

    def test_restore_from_db_records(self):
        """Credentials loaded from DB must be re-hydrated into vault correctly."""
        from ares.credential.vault import CredentialVault, Credential, CredentialType

        enc_key = "test-restore-vault-key-32chars!!"

        # Vault A: store a credential
        vault_a = CredentialVault(encryption_key=enc_key)
        cred    = Credential(
            id="cred-restore-001", campaign_id="camp-001",
            username="svc_sql", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            source_module="test",
        )
        vault_a.store(cred, "SuperSecret99!")

        stored      = vault_a._store["cred-restore-001"]
        secret_enc  = stored.secret_enc
        secret_str  = secret_enc.decode() if isinstance(secret_enc, bytes) else secret_enc

        # Simulate what DB returns
        db_records = [{
            "id":           "cred-restore-001",
            "campaign_id":  "camp-001",
            "username":     "svc_sql",
            "domain":       "CORP",
            "cred_type":    "cleartext",
            "secret_enc":   secret_str,
            "source_module": "test",
            "host_id":      None,
            "notes":        "",
        }]

        # Vault B: restore from DB — share salt/fernet for compatibility
        vault_b = CredentialVault(encryption_key=enc_key)
        vault_b._salt     = vault_a._salt
        vault_b._salt_hex = vault_a._salt_hex
        vault_b._fernet   = vault_a._fernet

        count = vault_b.restore_from_db_records(db_records)

        assert count == 1, f"Must restore 1 credential, got {count}"
        assert "cred-restore-001" in vault_b._store

        revealed = vault_b.reveal("cred-restore-001")
        assert revealed == "SuperSecret99!", (
            f"Revealed secret after restore must be 'SuperSecret99!', got {revealed!r}"
        )

    def test_empty_vault_persist_returns_zero(self):
        """_persist_vault_credentials on empty vault must return 0."""
        from ares.credential.vault import CredentialVault
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.engine import AresEngine

        db = MagicMock()
        db.save_credential_preencrypted = AsyncMock()

        campaign = Campaign(
            name="empty-vault-test", client="test",
            scope=[ScopeEntry(cidr="10.0.0.0/8")],
            noise_profile=NoiseProfile.NORMAL,
        )
        campaign._vault = CredentialVault(encryption_key=None)  # type: ignore

        engine = AresEngine(db=db)

        async def _run_test():
            saved = await engine._persist_vault_credentials(campaign)
            assert saved == 0
            db.save_credential_preencrypted.assert_not_called()
        _run(_run_test())

    def test_no_vault_on_campaign_is_safe(self):
        """Campaign without _vault attr must not crash _persist_vault_credentials."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.engine import AresEngine

        db    = MagicMock()
        db.save_credential_preencrypted = AsyncMock()
        campaign = Campaign(
            name="no-vault", client="test",
            scope=[ScopeEntry(cidr="10.0.0.0/8")],
            noise_profile=NoiseProfile.NORMAL,
        )
        # No _vault attr at all
        engine = AresEngine(db=db)

        async def _run_test():
            saved = await engine._persist_vault_credentials(campaign)
            assert saved == 0
        _run(_run_test())


# ══════════════════════════════════════════════════════════════════════
# TEST CLASS 6 — validate() ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════

class TestValidateEnforcement:
    """Engine must call validate() before execute() on every module run."""

    def test_validate_called_before_execute(self):
        """validate() must be called; execute() must NOT run if validate fails."""
        from ares.modules.base import BaseModule, OpsecLevel, ModuleResult
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.engine import AresEngine

        validate_calls: list[bool] = []
        execute_calls:  list[bool] = []

        class _StrictModule(BaseModule):
            MODULE_ID          = "test.strict_validate"
            MODULE_NAME        = "Strict Test"
            MODULE_CATEGORY    = "test"
            MODULE_DESCRIPTION = "Validation test module"
            OPSEC_LEVEL        = OpsecLevel.SILENT
            MITRE_TECHNIQUES   = []
            REQUIRES           = ["target"]
            OUTPUTS            = []

            async def validate(self, ctx):
                validate_calls.append(True)
                if not ctx.params.get("required_param"):
                    raise ModuleValidationError(
                        "required_param is missing",
                        module_id=self.MODULE_ID,
                        field="required_param",
                    )

            async def execute(self, ctx):
                execute_calls.append(True)
                return ModuleResult(status="success", findings=[], raw={},
                                    module_id=self.MODULE_ID)

        campaign = Campaign(
            name="validate-test", client="test",
            scope=[ScopeEntry(cidr="10.0.0.0/8")],
            noise_profile=NoiseProfile.NORMAL,
        )

        from ares.core.engine import ModuleRegistry as _Reg
        registry = _Reg()
        registry._registry = {"test.strict_validate": _StrictModule}

        engine = AresEngine()
        engine._registry = registry

        async def _run_test():
            from ares.core.config import get_settings
            get_settings.cache_clear()
            result = await engine.run_module(
                "test.strict_validate",
                campaign,
                params={"target": "10.0.0.1"},
                actor_role="team_lead",
                # No required_param — validate() must fail
            )
            assert len(validate_calls) == 1, "validate() must be called exactly once"
            assert len(execute_calls)  == 0, (
                "execute() must NOT run when validate() raises"
            )
            from ares.core.engine import ModuleStatus
            assert result.status == ModuleStatus.FAILED
            assert "required_param" in (result.error or "")
        _run(_run_test())

    def test_skip_validation_bypasses_validate(self):
        """skip_validation=True must bypass validate() and proceed to execute()."""
        from ares.modules.base import BaseModule, OpsecLevel, ModuleResult
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.engine import AresEngine

        validate_calls: list[bool] = []
        execute_calls:  list[bool] = []

        class _AlwaysFailValidate(BaseModule):
            MODULE_ID          = "test.always_fail_validate"
            MODULE_NAME        = "Always Fail Validate"
            MODULE_CATEGORY    = "test"
            MODULE_DESCRIPTION = "Skip validation test"
            OPSEC_LEVEL        = OpsecLevel.SILENT
            MITRE_TECHNIQUES   = []
            REQUIRES           = []
            OUTPUTS            = []

            async def validate(self, ctx):
                validate_calls.append(True)
                raise ModuleValidationError(
                    "always fails", module_id=self.MODULE_ID
                )

            async def execute(self, ctx):
                execute_calls.append(True)
                return ModuleResult(status="success", findings=[], raw={},
                                    module_id=self.MODULE_ID)

        campaign = Campaign(
            name="skip-validate-test", client="test",
            scope=[ScopeEntry(cidr="10.0.0.0/8")],
            noise_profile=NoiseProfile.NORMAL,
        )

        from ares.core.engine import ModuleRegistry as _Reg
        registry = _Reg()
        registry._registry = {"test.always_fail_validate": _AlwaysFailValidate}

        engine = AresEngine()
        engine._registry = registry

        async def _run_test():
            from ares.core.config import get_settings
            get_settings.cache_clear()
            result = await engine.run_module(
                "test.always_fail_validate",
                campaign,
                params={"target": "10.0.0.1"},
                skip_validation=True,
                actor_role="team_lead",
            )
            assert len(validate_calls) == 0, (
                "validate() must NOT be called when skip_validation=True"
            )
            assert len(execute_calls) == 1, (
                "execute() must run when validation is skipped"
            )
            from ares.core.engine import ModuleStatus
            assert result.status == ModuleStatus.DONE
        _run(_run_test())

    def test_targets_validation_rejects_path_traversal(self):
        """CampaignCreate must reject path traversal in targets."""
        from pydantic import ValidationError
        from ares.api.server import CampaignCreate

        with pytest.raises((ValidationError, ValueError)):
            CampaignCreate(
                name="test",
                targets=["../../../etc/passwd"],
            )

    def test_targets_validation_rejects_null(self):
        """CampaignCreate must reject None values in targets list."""
        from pydantic import ValidationError
        from ares.api.server import CampaignCreate

        with pytest.raises((ValidationError, ValueError)):
            CampaignCreate(
                name="test",
                targets=[None, "10.0.0.1"],  # type: ignore[list-item]
            )

    def test_targets_validation_accepts_valid(self):
        """CampaignCreate must accept valid IPs, CIDRs, and hostnames."""
        from ares.api.server import CampaignCreate

        c = CampaignCreate(
            name="test",
            targets=["10.0.0.1", "192.168.1.0/24", "dc01.corp.local"],
        )
        assert len(c.targets) == 3
        assert "10.0.0.1" in c.targets

    def test_targets_validation_filters_empty_strings(self):
        """CampaignCreate must silently drop empty/whitespace-only targets."""
        from ares.api.server import CampaignCreate

        c = CampaignCreate(
            name="test",
            targets=["", "  ", "10.0.0.1"],
        )
        assert c.targets == ["10.0.0.1"]
