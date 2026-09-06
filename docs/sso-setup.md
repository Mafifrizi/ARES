# Enterprise Single Sign-On (SSO) Integration & Setup Guide

This document provides a comprehensive guide for configuring and utilizing **Enterprise Multi-Tenant SSO (SAML 2.0 & OpenID Connect)** in the ARES Platform, covering both end-user workflows and administrative setup.

---

## PART 1 — End-User Authentication Guide

### When to Use Standard "Sign in" vs. "Or continue with SSO"

| Login Method | When to Use | Credentials |
| :--- | :--- | :--- |
| **Standard "Sign in"** | For local operator accounts and development/lab environments (e.g., the bootstrap superuser `admin` or dedicated local accounts created via `POST /auth/register`). | Local username and password stored in the ARES database (hashed via bcrypt). |
| **"Or continue with SSO"** | When your organization manages identities centrally via an Identity Provider (IdP) such as Okta, Microsoft Entra ID (Azure AD), Google Workspace, Ping Identity, or Keycloak. | Your corporate/organization credentials entered on your IdP's official sign-in page. |

> [!NOTE]
> **Federated Account Lockdown**: If your account has been provisioned or migrated to SSO (`auth_provider = 'saml'` or `'oidc'`), your account is **strictly prohibited** from authenticating with a local password. You must authenticate using the **"Or continue with SSO"** workflow.

### Understanding: *"SSO belum dikonfigurasi untuk organisasi ini. Hubungi admin."*

If you click **"Or continue with SSO"** and an inline warning appears:
> ⚠️ **SSO belum dikonfigurasi untuk organisasi ini. Hubungi admin.**  
> *(English translation: "SSO is not configured for this organization. Contact admin.")*

**What this means:**
1. SSO federation (SAML 2.0 or OIDC) has not yet been registered for the target organization, or the configuration is currently disabled (`is_enabled = 0`).
2. The ARES backend fail-closed policy rejected the request because no valid IdP endpoints, x.509 certificate, or client credentials were found.

**Action Required:**
- Do not attempt to guess local passwords.
- Contact your ARES Administrator or Security Operations (SecOps) team to complete the identity federation setup outlined in Part 2.

---

## PART 2 — Administrator Guide: Organization SSO Setup

### 1. Prerequisite: `ARES_ENCRYPTION_KEY` Environment Variable

ARES enforces application-level encryption for sensitive secrets at rest using the `DataEncryptor` module (Fernet-based: `PBKDF2-HMAC-SHA256` with 100,000 iterations + `AES-128-CBC` + `HMAC-SHA256` with a per-record cryptographically secure random salt). All SAML certificates and OIDC client secrets are encrypted before database persistence.

The application strictly requires `ARES_ENCRYPTION_KEY` to be **at least 32 characters long**. If unset or shorter than 32 characters, ARES will fail fast at startup with an explicit error.

#### Generate an Encryption Key:
Run the official Fernet generation command:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
*Example output: `16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w=`*

#### Set the Environment Variable:
- **In `.env` file (Recommended):**
  ```env
  ARES_ENCRYPTION_KEY=16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w=
  ```
- **In Linux / macOS (Terminal):**
  ```bash
  export ARES_ENCRYPTION_KEY="16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w="
  ```
- **In Windows (PowerShell):**
  ```powershell
  $env:ARES_ENCRYPTION_KEY="16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w="
  ```

---

### 2. Registering an SSO Configuration in ARES

SSO federation can be configured via the **REST API Admin Endpoints** (requires the `team_lead` role, the highest tier in ARES's role hierarchy: `team_lead > operator > recon > reporter`; the bootstrap user `admin` holds the `team_lead` role) or directly in the database.

> [!IMPORTANT]
> **Architecture Policy: SP-Initiated SSO Only**  
> ARES strictly supports **SP-initiated SSO**. Users must always begin their sign-in flow from the ARES login interface (by clicking *"Or continue with SSO"*), rather than launching the application from an IdP app portal (such as Okta Dashboard or Microsoft Entra ID / Azure AD My Apps).  
> **Communicate this requirement explicitly to your organization's IT/IAM team during onboarding**, as this differs from common SaaS defaults. ARES purposefully rejects unsolicited SAML assertions without an active `InResponseTo` record and OIDC callbacks without a registered `state` parameter to eliminate replay attacks and session-fixation risks.

#### Option A: Via REST API (Recommended)
ARES provides dedicated configuration management endpoints for `team_lead` users:
- **`GET /auth/sso/config/{org_slug}`**: Retrieve existing SSO status and metadata.
- **`POST /auth/sso/config/{org_slug}`**: Create or update organization SSO settings.

Request payload for `POST /auth/sso/config/{org_slug}`:
```json
{
  "protocol": "saml", // or "oidc"
  "issuer_or_entity_id": "https://idp.example.com/entityid",
  "sso_url": "https://idp.example.com/sso/endpoint",
  "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
  "client_id": "",
  "client_secret": "",
  "jwks_uri": "",
  "default_role": "reporter",
  "role_mapping": {
    "SecurityAdmins": "team_lead",
    "RedTeam": "operator",
    "Auditors": "reporter"
  },
  "is_enabled": true
}
```
*Note: The backend automatically encrypts `idp_certificate` and `client_secret` via `DataEncryptor` before persisting to `sso_configurations`.*

#### Option B: Direct SQL Database Insertion
If provisioning directly via SQLite (`ares.db`) or PostgreSQL:
1. Ensure the organization exists in the `organizations` table:
   ```sql
   INSERT INTO organizations (id, slug, name, is_active)
   VALUES ('org-corp-01', 'corp', 'ACME Corp', 1);
   ```
2. Encrypt certificates or client secrets using the ARES CLI helper:
   ```bash
   python -c "from ares.core.config import get_settings; from ares.core.sso import encrypt_sso_secret; print(encrypt_sso_secret('YOUR_SECRET_HERE', get_settings()))"
   ```
3. Insert into `sso_configurations`:
   ```sql
   INSERT INTO sso_configurations (
       id, org_id, protocol, is_enabled,
       issuer_or_entity_id, sso_url, idp_certificate_enc,
       default_role, role_mapping_json
   ) VALUES (
       'sso-cfg-01', 'org-corp-01', 'saml', 1,
       'https://idp.example.com/entityid', 'https://idp.example.com/sso', '<ENCRYPTED_VALUE>',
       'reporter', '{"SecAdmins": "team_lead"}'
   );
   ```

---

### 3. SAML 2.0 Integration Specifications

#### A. Required Parameters from the Organization's IdP:
1. **IdP Entity ID**: Unique URI identifying the IdP (e.g. `https://sts.windows.net/<tenant-uuid>/` or `http://www.okta.com/exk123`).
2. **Single Sign-On Service URL (SSO URL)**: IdP HTTP-Redirect or HTTP-POST endpoint where user AuthnRequests are sent.
3. **IdP x.509 Certificate**: IdP public signing certificate in PEM format to verify digital signatures on SAML assertions.

#### B. SP Parameters Provided by ARES to the IdP:
- **Assertion Consumer Service (ACS) URL**:
  ```
  POST https://<ares-domain>/auth/sso/saml/acs
  ```
  *(Binding: HTTP-POST)*
- **Service Provider (SP) Entity ID / Audience**:
  ```
  https://<ares-domain>/auth/sso/saml/metadata
  ```
- **NameID Format**: Email Address (`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`) or Persistent (`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`).

---

### 4. OpenID Connect (OIDC) Integration Specifications

#### A. Required Parameters from the Organization's IdP:
1. **Issuer URL**: Base URL of the provider (e.g. `https://accounts.google.com` or `https://login.microsoftonline.com/{tenant}/v2.0`).
2. **Client ID & Client Secret**: OAuth2 client credentials generated in the IdP app console.
3. **JWKS URI (Optional / Recommended)**: Public key set endpoint (e.g. `https://idp.example.com/.well-known/jwks.json`) for cryptographic ID Token verification.
4. **Authorization & Token Endpoints**: IdP OAuth2 authorization and token URLs.

#### B. Parameters Provided by ARES to the IdP:
- **Callback / Redirect URI**:
  ```
  GET https://<ares-domain>/auth/sso/oidc/callback
  ```
- **Grant Type**: Authorization Code (`response_type=code`).
- **Scopes**: `openid email profile`.

---

### 5. Verification & Testing Workflow

After saving the configuration, verify the setup without opening database tables:

1. **Verify Initiation Endpoint**:
   Query the initialization endpoint via cURL:
   ```bash
   curl -i "http://127.0.0.1:8080/auth/sso/init?org=default"
   ```
   **Expected Result**: HTTP `200 OK` with JSON response:
   ```json
   {
     "configured": true,
     "protocol": "saml", // or "oidc"
     "redirect_url": "https://idp.example.com/...",
     "flow_id": "..."
   }
   ```

2. **Verify End-to-End via ARES Dashboard UI**:
   - Navigate to `http://127.0.0.1:5173/dashboard/login`.
   - Click **"Or continue with SSO"**.
   - Your browser will seamlessly redirect to your corporate IdP login screen.
   - Enter your corporate credentials.
   - Upon successful IdP verification, you will be redirected back to the ARES Dashboard (`/dashboard/`) with active session cookies (`ares-dev-refresh` and `ares-dev-csrf`).
   - Your account is automatically provisioned Just-In-Time (JIT) with the appropriate role according to your claim mappings, defaulting safely to `reporter`.

---

## PART 3 — Troubleshooting Guide for Administrators

Common error messages returned in the login redirect URL (`/dashboard/login?error=...`) and their resolutions:

| Error Message | Root Cause | Administrative Resolution |
| :--- | :--- | :--- |
| **`Invalid or expired OIDC state (replay rejected)`** or<br>**`Invalid or expired SAML request ID (replay rejected)`** | The user took longer than 10 minutes to complete sign-in at the IdP, or the user navigated **Back**, refreshed the callback page, or replayed an expired authorization URL. | Instruct the user to return to `/dashboard/login` and click **"Or continue with SSO"** to generate a fresh, single-use authentication state. |
| **`SAML assertion missing InResponseTo (replay protection)`** | The IdP sent an assertion lacking the `InResponseTo` attribute, typically caused by initiating the login from an external IdP portal (*IdP-initiated SSO*). | ARES strictly enforces SP-initiated SSO to prevent token replay. Ensure operators initiate sign-in directly from the ARES login page. |
| **`Invalid SAML signature`** or<br>**`Signature validation failed`** | The stored IdP x.509 certificate does not match the private key used by the IdP to sign the assertion (e.g., following an IdP cert rotation or expiration). | Obtain the current x.509 public signing certificate from the IdP and update the configuration via `POST /auth/sso/config/{org_slug}`. |
| **`Invalid token issuer or audience`** (OIDC) | The `iss` (issuer) or `aud` (audience) claim in the IdP's JWT token does not match the configured `issuer_or_entity_id` or `client_id`. | Verify that the `client_id` and `issuer_or_entity_id` values in ARES match the exact client registration in your IdP console. |
| **`SSO configuration not found for organization`** | The requested organization has no active SSO profile, or `is_active = 0` / `is_enabled = 0`. | Verify that the organization is active in the `organizations` table and that its `sso_configurations` entry has `is_enabled = 1`. |
