# ARES Security Model

ARES is an offensive framework. This document explains how ARES protects the **operator**, **client data**, and **engagement scope** from accidental harm.

---

## Threat Model

### What we protect against

| Threat | Mitigation |
|--------|------------|
| Community module exfiltrates data | SandboxRunner isolation (subprocess/Docker) + module signatures |
| Credential data leaked to logs | structlog sensitive field masking, vault encryption |
| Out-of-scope host attacked | CampaignGuardrail scope check on every operation |
| Lockout caused by spray | AccountLocked error stops ALL attempts, AdaptiveOpsecEngine |
| Operator machine compromised | Encrypted checkpoints, no plaintext secrets on disk |
| API unauthorized access | JWT bearer tokens, bcrypt hashing, rate limiting |
| Replay attack on API | JWT expiry (1 hour default), nonce in sensitive endpoints |
| Module marketplace malware | SHA-256 signed manifests, trusted registry only |

### What we do NOT protect against

- Physical access to operator machine
- Compromise of the Redis/queue server (use TLS + auth)
- Legal liability for engagements without written authorization

---

## Encryption

### At Rest

| Data | Algorithm | Key Source |
|------|-----------|------------|
| Credential vault | Fernet (AES-128-CBC + HMAC-SHA256) | `ARES_ENCRYPTION_KEY` |
| Campaign checkpoints | Fernet | Same key |
| Evidence files | Fernet | Same key |
| API tokens | bcrypt (cost=12) | N/A (one-way hash) |

**Key management:** ARES uses two separate deployment secrets. The deployer or
client generates both; ARES does not ship a shared production key.

```bash
# Token/session signing key
export ARES_SECRET_KEY="$(openssl rand -hex 32)"

# Encryption key for vault, checkpoint, and stored sensitive material
export ARES_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

Never store these values in version control. Keep `ARES_ENCRYPTION_KEY` stable
and backed up securely; rotating it requires re-encrypting existing vault and
stored sensitive records.

### In Transit

- REST API: HTTPS (TLS 1.2+) — use a reverse proxy (nginx/caddy)
- WebSocket dashboard: WSS
- Redis cluster connection: `redis+tls://` with cert pinning
- Inter-worker: subprocess stdin/stdout (local only)

---

## Module Isolation (SandboxRunner)

### Isolation tiers

| Tier | Mechanism | Used for |
|------|-----------|---------|
| `NONE` | In-process | Core modules (trusted) |
| `SUBPROCESS` | Separate process + `resource.setrlimit` | Default for all modules |
| `SECCOMP` | Subprocess + seccomp syscall filter | High-risk community modules |
| `DOCKER` | Ephemeral container, `--rm` | Maximum isolation |

### Resource limits (SUBPROCESS tier)

```python
resource.setrlimit(RLIMIT_CPU,   (30, 30))      # 30 CPU seconds
resource.setrlimit(RLIMIT_AS,    (256MB, 256MB)) # 256 MB virtual memory
resource.setrlimit(RLIMIT_NPROC, (64, 64))       # 64 child processes
resource.setrlimit(RLIMIT_NOFILE,(256, 256))     # 256 open file descriptors
```

### What sandboxed modules cannot do

- Access core ARES engine state directly (communication via JSON stdin/stdout)
- Exceed CPU/memory limits without being killed
- Open more than 256 file descriptors
- On SECCOMP tier: call any syscall not in the allow-list

---

## API Security

### Authentication

Most API endpoints require a valid JWT bearer token or an API key:

```http
Authorization: Bearer eyJhbGci...
```

or:

```http
X-API-Key: ares_...
```

API keys are created after login from the Security page or
`POST /auth/api-keys`. They are not startup secrets. Use them for scripts,
CI jobs, internal integrations, or repeatable local validation where an
interactive browser session is not practical. The raw API key is shown only
once at creation time, is stored hashed, and can be revoked from the Security
page. In the dashboard, key creation opens the `Save your key` modal. The full
secret appears there once, `Copy` changes to `Copied` after a successful copy,
and `Done` closes the modal and clears the in-memory new-key state. The key
list shows metadata and a prefix only; the full secret cannot be retrieved
later.

API-key scopes are `read`, `write`, and `admin`. They are an additional
restriction on API-key-compatible automation routes and do not replace RBAC.
Use `X-API-Key` for automation endpoints such as `GET /auth/me`; account
credential management, user registration, and API-key lifecycle operations are
performed from an authenticated browser/JWT session.

**Unauthenticated endpoints** (by design):
- `POST /auth/token` — login (takes credentials, returns token)
- `GET /health` — health check (no sensitive data)

The supported dashboard is the React application served by the main ARES
FastAPI application at `/dashboard`. The older
`ares.api.dashboard.app:dashboard_app` FastAPI application is not mounted by
that topology. The executable guard's control objective is to prevent
accidental or default deployment of the legacy surface. Under normal ASGI
lifespan processing, legacy startup is denied unless both
`ARES_LEGACY_DASHBOARD_ENABLED=true` and `ARES_DEBUG=true`; the legacy flag
must never be enabled in production. Supported main-application, CLI, Docker,
and Compose launch paths use the main ARES application and normal lifecycle
processing, so they remain fail-closed by default.

The guard trusts the supported ASGI server to execute application lifespan.
Running the legacy target with lifespan disabled, including `--lifespan off`,
is unsupported. Directly dispatching HTTP or WebSocket request scopes without
managing lifespan is likewise unsupported and bypasses the startup guard. This
is operational containment for supported startup behavior, not parity
hardening or a security boundary against a malicious or privileged deployment
operator who deliberately bypasses ASGI lifespan.

The explicit opt-in does not give the legacy application modern
authentication, campaign-ownership, WebSocket, credential-transport, or
deployment parity. Query-token exposure and its global live-WebSocket design
remain. Full retirement is the preferred final control.

Tokens are issued by `POST /auth/token` with valid operator credentials
(bcrypt-hashed password). Each login creates an independent refresh-token
family with one active token, a 30-day absolute lifetime, and no sliding
extension. Only lowercase SHA-256 token hashes are stored. Access JWTs contain
`sub`, `sid`, `ver`, `jti`, `iat`, and `exp`; they contain no role claim.
Current database user status, role, authentication epoch, family state, and JTI
are authoritative on every bearer resolution. Default access expiry is one
hour.

Refresh is a one-winner database transaction. The predecessor is consumed and
exactly one child is inserted before commit; the raw child is returned only
after commit. Reuse of a known consumed or revoked predecessor atomically
revokes the complete family, including the committed winner after a concurrent
or lost-response retry. Unknown random values reveal nothing and mutate
nothing. `POST /auth/logout` revokes only the current family;
`POST /auth/logout-all`, password changes/resets, role changes, and activation
state changes increment the user epoch and revoke all families. Separate login
families remain isolated, and API keys never enter refresh families.

Family lineage is retained until 30 days after the later of family expiry or
revocation. Fixed security audit actions record login-family creation,
rotation, replay revocation, current/all-device logout, and account security
events without token, hash, family, user, SQL, or exception values.

### Main WebSocket tickets

The supported main campaign WebSocket never accepts a bearer token or API key
in its query string. A client authenticates `POST
/campaigns/{campaign_id}/websocket-ticket` with the normal bearer or API-key
header, then presents the returned ticket as the sole WebSocket query
parameter. Tickets have a 30-second issuance lifetime, are bound to one
campaign, and are globally single-use. A wrong-campaign presentation is denied
without consuming the ticket; replay and every legacy `token` or `api_key`
query form are denied.

Consumption is only the handshake authority. A connected socket retains an
opaque consumed handle and ARES revalidates the original current user,
bearer-expiry/JTI, API-key scope/lifetime/ownership, role, and campaign access
before protected events. This resolution is read-only and remains possible
after the ticket row expires or is purged. No registry entry retains a raw
ticket, bearer, API key, ticket hash, or original query string.

Bearer-backed tickets also bind the user authentication epoch and refresh
family. Family replay, logout, password/security events, expiry, or revocation
therefore deny ticket consumption and terminate connected bearer sockets on
the next heartbeat/event revalidation. API-key-backed tickets remain
independent of refresh families.

Tickets remain visible to the browser and any upstream component that receives
the handshake URL, so production clients must initiate HTTPS/WSS directly.
The production nginx TLS log uses `$uri`, which omits query strings. Its
port-80 redirect uses `$request_uri`; ticket-bearing plaintext requests at that
boundary are unsupported. The control does not claim to hide tickets from
browser developer tools or arbitrary third-party proxies.

Backend and frontend rollout is atomic: drain existing main WebSockets, deploy
both components together, and obtain a fresh ticket for every reconnect. Mixed
old/new component versions are unsupported. A rollback replaces both together
while leaving additive migrations installed. These controls do not change the
default-disabled legacy dashboard WebSocket or repair its known limitations.

### Authorization

ARES uses four account roles. Role values are lowercase in API requests:
`team_lead`, `operator`, `recon`, and `reporter`.

| Role | Intended use | Access model |
|------|--------------|--------------|
| `team_lead` | Engagement lead or local administrator. | Full API access, user registration, security audit, campaign deletion, restricted authorization, and normal operator work. |
| `operator` | Day-to-day operator. | Campaign workflows, module execution, reports, graph, artifacts, and standard validation flows. Cannot register users. |
| `recon` | Low-risk review/recon identity. | Read-heavy access. The module permission matrix marks enumeration, fingerprint, and network modules as recon-safe, but the main dashboard execution endpoints are still operator-gated in this release. |
| `reporter` | Reviewer or stakeholder. | Read-only campaign/report/graph-style access. No module execution and no user administration. |

The first account is bootstrapped as:

| Username | Role | Password source |
|----------|------|-----------------|
| `admin` | `team_lead` | `ARES_DEFAULT_ADMIN_PASSWORD` |

ARES creates that account only when the user table is empty. Changing
`ARES_DEFAULT_ADMIN_PASSWORD` after the `admin` account exists does not reset
the password. Use the Security page after login for normal password changes,
or recreate the local `ares.db` only when disposable local dashboard data can
be lost. Do not use local database reset guidance on real or shared
deployments.

Additional accounts are created by a `team_lead` through `POST /auth/register`.
The role is assigned at creation time:

```http
POST /auth/register
Authorization: Bearer <team-lead-token>
Content-Type: application/json

{
  "username": "alice",
  "password": "StrongPass1!",
  "role": "operator"
}
```

Valid role values are `team_lead`, `operator`, `recon`, and `reporter`.
Passwords must be at least 12 characters and include uppercase, lowercase,
numeric, and special-character content. The Security dashboard can list users,
but the current release does not expose a dashboard role editor for changing
an existing account's role.

### Rate limiting

- Default: 100 requests/minute per token
- Auth endpoint: 5 requests/minute per IP (lockout protection)
- WebSocket: 1 connection per operator

### Input validation

All request bodies validated by Pydantic v2 models. Any extra fields are rejected. SQL queries use parameterized statements via aiosqlite.

### Security headers

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

---

## Scope Enforcement

### CampaignGuardrail

Every module execution passes through `CampaignGuardrail.check()`:

1. **Sensitive range check**: 169.254.0.0/16 (AWS IMDS), 127.0.0.0/8 (loopback) — always blocked
2. **Scope CIDR check**: target must be in one of the campaign's declared scope CIDRs
3. **Dangerous module confirmation**: `ad.dcsync`, `lateral.psexec`, `linux.container` require `confirmed=True`

```python
allowed, reason = guardrail.check("ad.dcsync", "10.0.0.1")
# → False, "Module 'ad.dcsync' is HIGH-RISK. Pass confirmed=True to execute."

guardrail.confirm_dangerous("ad.dcsync", "10.0.0.1")
allowed, _ = guardrail.check("ad.dcsync", "10.0.0.1", confirmed=True)
# → True, "ok"
```

### ScopeGuard (NoiseController)

At the network level, `ScopeGuard.assert_in_scope(target)` is called in `BaseModule.before_request()` before every network call. Raises `ScopeError` (which is `ABORT` action — never retried).

---

## Audit Logging

All sensitive operations are written to the NDJSON audit log:

```json
{"event": "campaign_started", "actor": "alice", "campaign_id": "abc123", "timestamp": "..."}
{"event": "module_executed", "actor": "alice", "module": "ad.dcsync", "target": "dc01", "..."}
{"event": "credential_added", "actor": "engine", "username": "CORP\\Administrator", "..."}
{"event": "checkpoint_saved", "actor": "alice", "campaign_id": "abc123", "path": "..."}
{"event": "operator_joined", "actor": "bob", "role": "recon", "campaign_id": "..."}
```

Audit log location follows the supported logging configuration: ARES writes
`audit.ndjson` next to `ARES_LOG_FILE` (default: `logs/audit.ndjson`).

### Sensitive field masking

Passwords, hashes, and secret keys are automatically masked:

```python
# structlog processor strips these fields before writing
SENSITIVE_KEYS = {"password", "secret", "token", "hash", "key", "ntlm", "krb5"}
```

---

## Module Marketplace Security

### Signing

Each community module must be signed:

```bash
# Module author signs their module
ares-dev sign ./mymodule/ --key author.pem
# Produces manifest.json with "signature": "sha256:<hash>"
```

### Verification

Before installation, ARES verifies:

1. Manifest signature matches content hash
2. Author public key is in the trusted keyring
3. Module version matches the pinned version in manifest

### Trusted registry

The default trusted registry is `https://modules.ares-framework.io`. Operators can configure a private registry:

```toml
[marketplace]
registry_url = "https://internal-registry.corp.local"
trusted_keys = ["/etc/ares/trusted-keys/"]
```

---

## OpSec Posture

### AccountLocked handling

When `AccountLocked` is raised, the engine:
1. Immediately stops ALL further attempts against that account
2. Marks the account as locked in `OperatorSession`
3. Logs at ERROR level: `account_locked` event
4. Notifies the operator via dashboard WebSocket

### DetectionSignal handling

`AdaptiveOpsecEngine` monitors for:
- 3 timeouts in 60s → escalate profile
- 5 connection resets in 60s → blacklist host 5 min
- 3 auth failures in 60s → stop account
- `RATE_LIMITED` response → double jitter
- `SCAN_DETECTED` → pause all activity, switch to `stealth`

### HoneypotDetected handling

Campaign is paused immediately. Operator is notified. No further network activity until operator runs `ares campaign resume --confirmed`.

---

## Responsible Use

ARES is intended for:
- Authorized penetration testing engagements
- Red team exercises with written client authorization
- Purple team exercises and security training
- Internal security research

**Do not use ARES against systems you do not own or have explicit written permission to test.**

Anthropic and the ARES authors take no responsibility for misuse.
