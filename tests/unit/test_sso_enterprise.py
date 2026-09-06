"""
Unit and integration tests for ARES Multi-Tenant Enterprise SSO (SAML 2.0 / OIDC).
Validates:
1. Encryption key length requirement (ARES_ENCRYPTION_KEY >= 32)
2. App-level encryption for certs and secrets
3. Schema reconciliation for organizations and SSO tables
4. One-time ephemeral flow state (Anti-replay protection)
5. JIT user provisioning with role mapping (default to reporter)
6. Explicit blocking of SSO users from local password login
7. Endpoint /auth/sso/init error behavior on unconfigured organizations
8. SAML & OIDC error and callback handling
"""

import asyncio
import json
import os
import secrets
from unittest.mock import AsyncMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from ares.core.config import AresSettings, get_settings
from ares.core.security import DataEncryptor, hash_password
from ares.core.sso import (
    decrypt_sso_secret,
    encrypt_sso_secret,
    map_idp_role,
)
from ares.db.database import AresDatabase


@pytest.fixture
def test_settings():
    return AresSettings(
        ares_secret_key="test-secret-key-must-be-min-32-chars-long!",
        ares_encryption_key="test-encryption-key-min-32-chars-fernet!",
        ares_default_admin_password="TestPassword123!",
    )


@pytest.mark.asyncio
async def test_encryption_key_validation():
    """Verify DataEncryptor enforces key length >= 32 and fails otherwise."""
    with pytest.raises(ValueError, match="at least 32 characters"):
        DataEncryptor("short-key")

    encryptor = DataEncryptor("valid-encryption-key-that-is-at-least-32-chars!")
    ciphertext = encryptor.encrypt("super-secret-cert-or-token")
    assert ciphertext is not None
    assert ":" in ciphertext
    decrypted = encryptor.decrypt(ciphertext)
    assert decrypted == "super-secret-cert-or-token"


@pytest.mark.asyncio
async def test_app_level_secret_encryption_helpers(test_settings):
    """Verify encrypt_sso_secret and decrypt_sso_secret."""
    plain = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----"
    encrypted = encrypt_sso_secret(plain, test_settings)
    assert encrypted != plain
    assert ":" in encrypted
    decrypted = decrypt_sso_secret(encrypted, test_settings)
    assert decrypted == plain


def test_role_mapping_least_privilege_fallback():
    """Verify IdP claims map to roles, and default strictly to reporter."""
    mapping = json.dumps({
        "SecAdmins": "team_lead",
        "RedTeamers": "operator",
        "Auditors": "reporter",
    })

    # Exact group match
    assert map_idp_role({"groups": ["RedTeamers"]}, mapping) == "operator"
    assert map_idp_role({"roles": ["SecAdmins"]}, mapping) == "team_lead"

    # Unknown group -> strictly reporter
    assert map_idp_role({"groups": ["UnknownGroup"]}, mapping) == "reporter"

    # Empty claims -> strictly reporter
    assert map_idp_role({}, mapping) == "reporter"

    # Direct role name in claim
    assert map_idp_role({"roles": ["operator"]}, None) == "operator"

    # Never escalate to admin on invalid/empty mapping
    assert map_idp_role({"groups": ["CEO"]}, None, default_role="invalid") == "reporter"


@pytest.mark.asyncio
async def test_database_sso_schema_and_operations(tmp_path, test_settings):
    """Test organization, sso config, flow state, and JIT provisioning in SQLite."""
    db_file = tmp_path / "test_sso.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    try:
        # 1. Organization creation & retrieval
        org = await db.get_organization("default")
        assert org is not None
        assert org["slug"] == "default"

        # 2. SSO configuration saving & retrieval
        cert_enc = encrypt_sso_secret("MOCK_CERT", test_settings)
        sec_enc = encrypt_sso_secret("MOCK_SECRET", test_settings)

        sso_id = await db.save_sso_config(
            org_id=org["id"],
            protocol="oidc",
            issuer_or_entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/authorize",
            client_id="ares-client",
            client_secret_enc=sec_enc,
            acs_url="https://idp.example.com/token",
            jwks_uri="https://idp.example.com/.well-known/jwks.json",
            default_role="reporter",
            role_mapping_json=json.dumps({"Engineers": "operator"}),
        )
        assert sso_id is not None

        cfg = await db.get_sso_config(org["id"], protocol="oidc")
        assert cfg is not None
        assert cfg["issuer_or_entity_id"] == "https://idp.example.com"
        assert cfg["client_secret_enc"] == sec_enc

        # 3. Flow state one-time replay protection
        flow_id = "test-state-token-123"
        nonce = "test-nonce-456"
        await db.create_sso_flow_state(org["id"], "oidc", flow_id, nonce=nonce, ttl_minutes=5)

        # First consumption must succeed
        consumed = await db.consume_sso_flow_state(flow_id, "oidc")
        assert consumed is not None
        assert consumed["flow_id"] == flow_id
        assert consumed["nonce"] == nonce

        # Second consumption (replay attack) MUST fail
        replayed = await db.consume_sso_flow_state(flow_id, "oidc")
        assert replayed is None

        # 4. JIT User Provisioning
        user = await db.provision_or_get_sso_user(
            org_id=org["id"],
            username="sso_analyst",
            role="operator",
            external_id="idp-user-sub-999",
            auth_provider="oidc",
        )
        assert user is not None
        assert user["username"] == "sso_analyst"
        assert user["role"] == "operator"
        assert user["auth_provider"] == "oidc"
        assert user["external_subject_id"] == "idp-user-sub-999"

        # Lookup same user on subsequent login
        user2 = await db.provision_or_get_sso_user(
            org_id=org["id"],
            username="sso_analyst",
            role="operator",
            external_id="idp-user-sub-999",
            auth_provider="oidc",
        )
        assert user2["id"] == user["id"]

        # 5. EXPLICIT REJECT: SSO user cannot authenticate via local password
        password_attempt = await db.verify_user("sso_analyst", "AnyPasswordTry")
        assert password_attempt is None

    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sso_init_unconfigured_error(tmp_path):
    """Verify /auth/sso/init returns inline-compatible 400 error on unconfigured org."""
    from ares.api.server import app, get_db

    db_file = tmp_path / "test_api_sso.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    app.dependency_overrides[get_db] = lambda: db

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            resp = await client.get("/auth/sso/init?org=default")
            assert resp.status_code == 400
            data = resp.json()
            assert "SSO belum dikonfigurasi untuk organisasi ini. Hubungi admin." in data.get("detail", "")
    finally:
        app.dependency_overrides.pop(get_db, None)
        await db.close()


@pytest.mark.asyncio
async def test_sso_init_configured_success(tmp_path, test_settings):
    """Verify /auth/sso/init returns redirect_url and records one-time flow state."""
    from ares.api.server import app, get_db

    db_file = tmp_path / "test_api_sso_configured.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    org = await db.get_organization("default")
    await db.save_sso_config(
        org_id=org["id"],
        protocol="oidc",
        issuer_or_entity_id="https://auth.company.com",
        sso_url="https://auth.company.com/oauth2/v1/authorize",
        client_id="ares-sec",
        acs_url="https://auth.company.com/oauth2/v1/token",
    )

    app.dependency_overrides[get_db] = lambda: db

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            resp = await client.get("/auth/sso/init?org=default")
            assert resp.status_code == 200
            data = resp.json()
            assert data["configured"] is True
            assert data["protocol"] == "oidc"
            assert "https://auth.company.com/oauth2/v1/authorize" in data["redirect_url"]
            assert "state=" in data["redirect_url"]
            assert "nonce=" in data["redirect_url"]

            # Flow state must be recorded in DB
            flow_id = data["flow_id"]
            flow_row = await db.consume_sso_flow_state(flow_id, "oidc")
            assert flow_row is not None
            assert flow_row["flow_id"] == flow_id
    finally:
        app.dependency_overrides.pop(get_db, None)
        await db.close()


@pytest.mark.asyncio
async def test_sso_user_blocked_at_auth_token_endpoint(tmp_path):
    """Verify /auth/token explicitly rejects login attempts for SSO users, even with bcrypt match."""
    from ares.api.server import app, get_db

    db_file = tmp_path / "test_auth_token_block.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    # Create an SSO-provisioned user in the database
    org = await db.get_organization("default")
    await db.provision_or_get_sso_user(
        org_id=org["id"],
        username="enterprise_sso_user",
        role="operator",
        external_id="ext-123",
        auth_provider="oidc",
    )

    app.dependency_overrides[get_db] = lambda: db

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:5173") as client:
            csrf_res = await client.get("/auth/csrf", headers={"Origin": "http://127.0.0.1:5173"})
            assert csrf_res.status_code == 204
            csrf_token = client.cookies.get("ares-dev-csrf")
            assert csrf_token is not None

            resp = await client.post(
                "/auth/token",
                data={"username": "enterprise_sso_user", "password": "AnyPasswordTry!"},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "http://127.0.0.1:5173",
                    "Sec-Fetch-Site": "same-origin",
                    "X-ARES-CSRF": csrf_token,
                },
            )
            assert resp.status_code == 401
            assert resp.json().get("detail") == "Invalid credentials"
    finally:
        app.dependency_overrides.pop(get_db, None)
        await db.close()


@pytest.mark.asyncio
async def test_oidc_callback_replay_and_state_validation(tmp_path, test_settings):
    """Verify OIDC callback enforces state match, consumes state atomically, and redirects with cookies."""
    from ares.api.server import app, get_db

    db_file = tmp_path / "test_oidc_callback.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    org = await db.get_organization("default")
    await db.save_sso_config(
        org_id=org["id"],
        protocol="oidc",
        issuer_or_entity_id="https://idp.example.com",
        sso_url="https://idp.example.com/auth",
        client_id="ares-app",
        acs_url="https://idp.example.com/token",
    )

    # Pre-create flow state
    valid_state = "valid-state-" + secrets.token_hex(16)
    valid_nonce = "valid-nonce-" + secrets.token_hex(16)
    await db.create_sso_flow_state(org["id"], "oidc", valid_state, nonce=valid_nonce, ttl_minutes=5)

    app.dependency_overrides[get_db] = lambda: db

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            # 1. Unknown or forged state -> 303 redirect with error param
            forged_resp = await client.get(
                "/auth/sso/oidc/callback?state=forged-state&code=test-code",
                follow_redirects=False,
            )
            assert forged_resp.status_code == 303
            assert "/dashboard/login?error=" in forged_resp.headers["location"]

            # 2. Mock process_oidc_callback to simulate successful IdP response
            with patch("ares.api.server.process_oidc_callback", new_callable=AsyncMock) as mock_oidc:
                mock_oidc.return_value = {
                    "external_id": "okta-sub-456",
                    "username": "alice_secops",
                    "role": "operator",
                    "claims": {"sub": "okta-sub-456", "email": "alice@secops.corp"},
                }

                # First callback with valid state -> 303 redirect to /dashboard/ and cookies set
                resp = await client.get(
                    f"/auth/sso/oidc/callback?state={valid_state}&code=mock-auth-code",
                    follow_redirects=False,
                )
                assert resp.status_code == 303
                assert resp.headers["location"] == "/dashboard/"
                assert ("ares-dev-refresh" in resp.cookies) or ("__Host-ares-refresh" in resp.cookies)
                assert ("ares-dev-csrf" in resp.cookies) or ("__Host-ares-csrf" in resp.cookies)

                # 3. Replay attack: calling the same callback again with same state -> 303 with replay error
                replay_resp = await client.get(
                    f"/auth/sso/oidc/callback?state={valid_state}&code=mock-auth-code",
                    follow_redirects=False,
                )
                assert replay_resp.status_code == 303
                assert "/dashboard/login?error=" in replay_resp.headers["location"]
    finally:
        app.dependency_overrides.pop(get_db, None)
        await db.close()


@pytest.mark.asyncio
async def test_saml_acs_replay_and_in_response_to_validation(tmp_path, test_settings):
    """Verify SAML ACS callback validates InResponseTo, rejects cross-site replay without CSRF header check."""
    import base64
    from ares.api.server import app, get_db

    db_file = tmp_path / "test_saml_acs.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    org = await db.get_organization("default")
    await db.save_sso_config(
        org_id=org["id"],
        protocol="saml",
        issuer_or_entity_id="https://saml-idp.example.com",
        sso_url="https://saml-idp.example.com/sso",
        sp_entity_id="https://ares.local/auth/sso/saml/metadata",
        acs_url="http://localhost/auth/sso/saml/acs",
    )

    valid_request_id = "REQ-" + secrets.token_hex(16)
    await db.create_sso_flow_state(org["id"], "saml", valid_request_id, ttl_minutes=5)

    app.dependency_overrides[get_db] = lambda: db

    mismatch_xml = base64.b64encode(
        b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="DIFFERENT-REQ-ID"></samlp:Response>'
    ).decode("ascii")
    valid_xml = base64.b64encode(
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="{valid_request_id}"></samlp:Response>'.encode("ascii")
    ).decode("ascii")

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            # Note: No X-ARES-CSRF header sent! This tests CSRF exemption on ACS endpoint.
            with patch("ares.api.server.process_saml_response") as mock_saml:
                # 1. SAML response with mismatched InResponseTo -> 303 redirect with error
                mismatch_resp = await client.post(
                    "/auth/sso/saml/acs",
                    data={"SAMLResponse": mismatch_xml},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
                assert mismatch_resp.status_code == 303
                assert "/dashboard/login?error=" in mismatch_resp.headers["location"]

                # 2. SAML response with matching InResponseTo -> 303 redirect to /dashboard/ + cookies
                mock_saml.return_value = {
                    "in_response_to": valid_request_id,
                    "name_id": "bob@security.corp",
                    "username": "bob_sso",
                    "role": "reporter",
                    "external_id": "bob-idp-sub",
                    "attributes": {},
                }
                success_resp = await client.post(
                    "/auth/sso/saml/acs",
                    data={"SAMLResponse": valid_xml},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
                assert success_resp.status_code == 303
                assert success_resp.headers["location"] == "/dashboard/"
                assert ("ares-dev-refresh" in success_resp.cookies) or ("__Host-ares-refresh" in success_resp.cookies)
                assert ("ares-dev-csrf" in success_resp.cookies) or ("__Host-ares-csrf" in success_resp.cookies)

                # 3. Replay attack with same SAMLResponse / Request ID -> 303 redirect with replay error
                replay_resp = await client.post(
                    "/auth/sso/saml/acs",
                    data={"SAMLResponse": valid_xml},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
                assert replay_resp.status_code == 303
                assert "/dashboard/login?error=" in replay_resp.headers["location"]
    finally:
        app.dependency_overrides.pop(get_db, None)
        await db.close()


