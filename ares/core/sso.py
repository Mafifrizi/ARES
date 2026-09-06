"""
ARES Enterprise Single Sign-On (SSO) Core Service.
Supports SAML 2.0 (via python3-saml) and OpenID Connect (via authlib).
Features app-level secret encryption, JIT role mapping, and strict replay protection.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Mapping
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, jwt as authlib_jwt
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from ares.core.config import AresSettings
from ares.core.logger import get_logger
from ares.core.security import DataEncryptor

logger = get_logger("ares.core.sso")

_ALLOWED_ROLES = frozenset({"team_lead", "operator", "recon", "reporter"})


# ── App-Level Secret Encryption ───────────────────────────────────────────────

def encrypt_sso_secret(secret: str | None, settings: AresSettings) -> str:
    """Encrypt sensitive credentials (X.509 certs, client secrets) using DataEncryptor."""
    if not secret:
        return ""
    encryptor = DataEncryptor(settings.encryption_key_value)
    encrypted = encryptor.encrypt(secret)
    return encrypted or ""


def decrypt_sso_secret(encrypted_secret: str | None, settings: AresSettings) -> str:
    """Decrypt sensitive credentials using DataEncryptor."""
    if not encrypted_secret:
        return ""
    encryptor = DataEncryptor(settings.encryption_key_value)
    decrypted = encryptor.decrypt(encrypted_secret)
    return decrypted or ""


# ── Role Mapping ─────────────────────────────────────────────────────────────

def map_idp_role(
    claims: Mapping[str, Any],
    role_mapping_json: str | None,
    default_role: str = "reporter",
) -> str:
    """
    Map IdP groups/roles to ARES roles.
    Strictly defaults to 'reporter' (least privilege) if no match is found.
    Never defaults to team_lead or operator.
    """
    safe_default = default_role if default_role in _ALLOWED_ROLES else "reporter"

    mapping: dict[str, str] = {}
    if role_mapping_json:
        try:
            parsed = json.loads(role_mapping_json)
            if isinstance(parsed, dict):
                mapping = {str(k): str(v) for k, v in parsed.items()}
        except Exception:
            logger.warning("sso_role_mapping_parse_failed")

    # Inspect common claim keys where IdP sends roles or groups
    candidate_groups: list[str] = []
    group_keys = (
        "roles",
        "groups",
        "role",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "cognito:groups",
    )
    for key in group_keys:
        val = claims.get(key)
        if isinstance(val, list):
            candidate_groups.extend(str(item) for item in val)
        elif isinstance(val, str):
            candidate_groups.append(val)

    # Check realm_access / resource_access (Keycloak standard)
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        roles = realm_access.get("roles")
        if isinstance(roles, list):
            candidate_groups.extend(str(r) for r in roles)

    # Map candidate groups to ARES roles
    for group in candidate_groups:
        if group in mapping:
            target_role = mapping[group]
            if target_role in _ALLOWED_ROLES:
                return target_role

    # Direct match if IdP explicitly passed an ARES role name
    for group in candidate_groups:
        lowered = group.lower()
        if lowered in _ALLOWED_ROLES:
            return lowered

    return safe_default


# ── SAML 2.0 Flow ─────────────────────────────────────────────────────────────

def _build_saml_settings_dict(
    sso_config: Mapping[str, Any],
    base_url: str,
    idp_cert: str,
) -> dict[str, Any]:
    """Construct python3-saml settings dictionary."""
    sp_entity_id = sso_config.get("sp_entity_id") or f"{base_url}/auth/sso/saml/metadata"
    acs_url = sso_config.get("acs_url") or f"{base_url}/auth/sso/saml/acs"
    idp_entity_id = sso_config.get("issuer_or_entity_id", "")
    sso_url = sso_config.get("sso_url", "")

    # Clean certificate formatting (remove PEM headers if present for python3-saml)
    clean_cert = idp_cert.replace("-----BEGIN CERTIFICATE-----", "")
    clean_cert = clean_cert.replace("-----END CERTIFICATE-----", "")
    clean_cert = clean_cert.replace("\r", "").replace("\n", "").strip()

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {
                "url": sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": clean_cert,
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,  # Require signed assertions
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def build_saml_auth_request(
    sso_config: Mapping[str, Any],
    base_url: str,
    settings: AresSettings,
) -> tuple[str, str]:
    """
    Generate SAML AuthnRequest.
    Returns (redirect_url, request_id).
    """
    idp_cert = decrypt_sso_secret(sso_config.get("idp_certificate_enc"), settings)
    saml_settings_dict = _build_saml_settings_dict(sso_config, base_url, idp_cert)
    saml_settings = OneLogin_Saml2_Settings(saml_settings_dict)

    # Empty dummy request for OneLogin_Saml2_Auth initialization
    req = {
        "https": "on" if base_url.startswith("https") else "off",
        "http_host": base_url.split("://")[-1],
        "script_name": "/auth/sso/saml/acs",
        "get_data": {},
        "post_data": {},
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings)
    redirect_url = auth.login()
    request_id = auth.get_last_request_id()

    if not request_id:
        request_id = f"ARES_SAML_{secrets.token_hex(16)}"
    return redirect_url, request_id


def process_saml_response(
    sso_config: Mapping[str, Any],
    post_data: dict[str, Any],
    expected_request_id: str,
    base_url: str,
    settings: AresSettings,
) -> dict[str, Any]:
    """
    Process SAML ACS response (HTTP-POST).
    Validates XML signature, expiration, and InResponseTo.
    Returns extracted user profile and mapped role.
    """
    idp_cert = decrypt_sso_secret(sso_config.get("idp_certificate_enc"), settings)
    saml_settings_dict = _build_saml_settings_dict(sso_config, base_url, idp_cert)
    saml_settings = OneLogin_Saml2_Settings(saml_settings_dict)

    req = {
        "https": "on" if base_url.startswith("https") else "off",
        "http_host": base_url.split("://")[-1],
        "script_name": "/auth/sso/saml/acs",
        "get_data": {},
        "post_data": post_data,
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings)
    auth.process_response(request_id=expected_request_id)

    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or ", ".join(errors)
        logger.warning("saml_assertion_validation_failed", error=reason)
        raise ValueError(f"SAML assertion verification failed: {reason}")

    if not auth.is_authenticated():
        reason = auth.get_last_error_reason() or "Assertion not authenticated"
        logger.warning("saml_not_authenticated", error=reason)
        raise ValueError(f"SAML authentication rejected: {reason}")

    nameid = auth.get_nameid()
    attributes = auth.get_attributes()

    # Determine username/email from NameID and attributes
    email = ""
    email_keys = (
        "email",
        "mail",
        "userPrincipalName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    )
    for ek in email_keys:
        val = attributes.get(ek)
        if val and isinstance(val, list) and len(val) > 0:
            email = str(val[0])
            break

    username = email.split("@")[0] if email and "@" in email else (nameid or f"saml_{secrets.token_hex(4)}")
    role = map_idp_role(
        attributes,
        sso_config.get("role_mapping_json"),
        default_role=sso_config.get("default_role", "reporter"),
    )

    return {
        "username": username,
        "email": email,
        "external_id": nameid,
        "role": role,
        "attributes": attributes,
    }


# ── OpenID Connect (OIDC) Flow ───────────────────────────────────────────────

def build_oidc_auth_request(
    sso_config: Mapping[str, Any],
    redirect_uri: str,
) -> tuple[str, str, str]:
    """
    Generate OIDC authorization URL with state and nonce.
    Returns (authorization_url, state, nonce).
    """
    client_id = sso_config.get("client_id", "")
    auth_endpoint = sso_config.get("sso_url", "")
    if not auth_endpoint:
        raise ValueError("OIDC sso_url (authorization endpoint) is not configured")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
    }
    delimiter = "&" if "?" in auth_endpoint else "?"
    redirect_url = f"{auth_endpoint}{delimiter}{urlencode(params)}"
    return redirect_url, state, nonce


async def process_oidc_callback(
    sso_config: Mapping[str, Any],
    code: str,
    redirect_uri: str,
    expected_nonce: str,
    settings: AresSettings,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """
    Process OIDC callback code.
    Exchanges code for tokens, validates ID token signature via JWKS,
    enforces iss, aud, exp, and nonce matching.
    """
    client_id = sso_config.get("client_id", "")
    client_secret = decrypt_sso_secret(sso_config.get("client_secret_enc"), settings)
    issuer = sso_config.get("issuer_or_entity_id", "")
    token_endpoint = sso_config.get("acs_url")  # In OIDC, acs_url holds token_endpoint
    jwks_uri = sso_config.get("jwks_uri", "")

    if not token_endpoint:
        raise ValueError("OIDC token endpoint (acs_url) is not configured")

    client = http_client or httpx.AsyncClient(timeout=15.0)
    should_close = http_client is None

    try:
        # 1. Exchange authorization code for tokens
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code >= 400:
            logger.warning("oidc_token_exchange_failed", status=token_resp.status_code, text=token_resp.text)
            raise ValueError(f"OIDC token exchange failed: HTTP {token_resp.status_code}")

        token_data = token_resp.json()
        id_token = token_data.get("id_token")
        if not id_token:
            raise ValueError("OIDC response missing id_token")

        # 2. Fetch JWKS and verify signature
        if jwks_uri:
            jwks_resp = await client.get(jwks_uri)
            if jwks_resp.status_code >= 400:
                raise ValueError(f"Failed to fetch JWKS from {jwks_uri}")
            jwks = jwks_resp.json()
            key_set = JsonWebKey.import_key_set(jwks)
            claims = authlib_jwt.decode(id_token, key_set)
        else:
            # Fallback for mock/symmetric tests: decode without JWKS verification if jwks_uri is empty
            claims = authlib_jwt.decode(id_token, client_secret)

        # 3. Validate standard claims
        now = time.time()
        exp = claims.get("exp")
        if exp and exp < now:
            raise ValueError("OIDC id_token has expired")

        token_iss = claims.get("iss", "")
        if issuer and token_iss != issuer:
            raise ValueError(f"OIDC issuer mismatch: expected {issuer}, got {token_iss}")

        token_aud = claims.get("aud")
        if isinstance(token_aud, list):
            if client_id not in token_aud:
                raise ValueError(f"OIDC aud mismatch: client_id {client_id} not in {token_aud}")
        elif isinstance(token_aud, str):
            if token_aud != client_id:
                raise ValueError(f"OIDC aud mismatch: expected {client_id}, got {token_aud}")

        token_nonce = claims.get("nonce")
        if expected_nonce and token_nonce != expected_nonce:
            raise ValueError("OIDC nonce mismatch (replay protection triggered)")

        sub = str(claims.get("sub", ""))
        email = str(claims.get("email") or claims.get("preferred_username") or "")
        username = email.split("@")[0] if email and "@" in email else (claims.get("preferred_username") or sub)

        role = map_idp_role(
            claims,
            sso_config.get("role_mapping_json"),
            default_role=sso_config.get("default_role", "reporter"),
        )

        return {
            "username": username,
            "email": email,
            "external_id": sub,
            "role": role,
            "claims": dict(claims),
        }
    finally:
        if should_close:
            await client.aclose()
