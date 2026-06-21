# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.x     | ✅ Active security fixes |
| 5.x     | ❌ End of life — upgrade to v6 |
| < 5.0   | ❌ End of life |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### How to report

Email: **security@ares-framework.io**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations (optional)

PGP key: Generate and publish your PGP key before making this repository public.
Upload to a public keyserver (keys.openpgp.org) and link it here.

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix development | 30 days for critical, 90 days for medium |
| Public disclosure | After fix is released + 7 days |

We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/CVD).

---

## Scope

### In scope
- Authentication bypass in the ARES API (`ares/api/`)
- Credential exposure — vault encryption, log redaction failures
- RBAC bypass — escalating from `reporter` to `operator` or `team_lead`
- SQL injection or command injection in any module input handling
- Scope guard bypass — running modules against out-of-scope targets
- Dependency vulnerabilities with direct exploitability in ARES context

### Out of scope
- Issues in modules that require compromising the target first (by design — ARES is a red team tool)
- Denial of service against the ARES API
- Issues in `[dev]` optional dependencies
- Social engineering

---

## Security Design

### API Response Data — Intentional Sensitive Output

`EngineModuleResult.raw_output` in API responses intentionally contains
captured hashes, Kerberos tickets, and credentials. This is the core value
of a red team tool — the operator needs this data to continue the engagement.

Protections applied to this data:

| Protection | Implementation |
|-----------|----------------|
| Authentication | `require_operator()` — only authenticated operators can run modules |
| Authorization | RBAC — `reporter` and `recon` roles cannot run credential modules |
| Transport | HTTPS enforced via nginx TLS + HSTS |
| Caching | `Cache-Control: no-store` on all API responses |
| Rate limiting | Per-endpoint limits prevent bulk extraction |
| Audit log | Every `module_run_start` and `module_run_complete` is logged with actor |

Operators should treat ARES API responses with the same sensitivity as
the data they contain — store engagement results in encrypted storage.

## Security Design

Key security controls in ARES v6:

| Control | Implementation |
|---------|---------------|
| Credential encryption | Fernet with per-record PBKDF2-SHA256 salt (100,000 iterations) |
| Legacy encryption | Configurable via `ARES_LEGACY_SALT` env var |
| JWT tokens | HS256 default; RS256 supported via `ARES_JWT_ALGORITHM=RS256` |
| Token revocation | JTI blacklist — logout immediately invalidates tokens |
| Scope enforcement | `ScopeGuard` hard-stops all modules; fails closed |
| Log redaction | Hashes, passwords, JWTs stripped from all structlog output |
| STEALTH enforcement | HIGH_NOISE modules raise `ModuleValidationError` before any network call |
| Subprocess isolation | Module crashes cannot affect the engine process |
| Input sanitization | `sanitize_ldap()` and `sanitize_hostname()` at 48+ call sites |

---

## Known Security Considerations

**This is a red team framework.** It is designed to perform attacks against
authorized targets. Deploying it in unauthorized environments is illegal.

Always:
- Obtain written authorization before running any ARES module
- Set scope via `ares campaign create --targets <cidr>` before running modules
- Use `--noise stealth` for sensitive engagements
- Rotate `ARES_SECRET_KEY` and `ARES_ENCRYPTION_KEY` between engagements

---

*This policy was last updated: 2026-03-21*
