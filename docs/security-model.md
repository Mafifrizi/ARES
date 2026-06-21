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
| Credential vault | Fernet (AES-128-CBC + HMAC-SHA256) | `secret_key` in settings (SHA-256 derived) |
| Campaign checkpoints | Fernet | Same key |
| Evidence files | Fernet | Same key |
| API tokens | bcrypt (cost=12) | N/A (one-way hash) |

**Key management:** The `secret_key` is loaded from environment variable `ARES_SECRET_KEY`. Never store it in version control. Rotate it by re-encrypting all vault entries.

```bash
# Generate a strong key
python3 -c "import secrets; print(secrets.token_hex(32))"
export ARES_SECRET_KEY=<output>
```

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

**Unauthenticated endpoints** (by design):
- `POST /auth/token` — login (takes credentials, returns token)
- `GET /health` — health check (no sensitive data)

**Dashboard sub-application** (`/dashboard/*`) uses the same JWT / API-key
tokens but validates them independently via `Authorization: Bearer` header
or `?token=<jwt>` query param (WebSocket only).

Tokens are issued by `POST /auth/token` with valid operator credentials (bcrypt-hashed password). Default expiry: 1 hour.

### Authorization

| Role | Endpoints |
|------|-----------|
| `team_lead` | All endpoints |
| `operator` | `/campaign`, `/module`, `/artifacts`, `/report` |
| `recon` | Read-only + enumeration module endpoints |
| `reporter` | Read-only: `/campaign/{id}`, `/report` |

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

Log location: `~/.ares/audit.ndjson` (configurable via `ARES_AUDIT_LOG`).

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
