<div align="center">

<img src="frontend/public/brand/ares-logo.png" alt="ARES" width="460">

# ARES

### Automated Red Team Engagement System

ARES is an authorized red-team engagement framework for scoped campaigns,
module orchestration, OPSEC-aware execution, encrypted credential handling,
and professional report generation.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Dashboard-React-61DAFB?style=for-the-badge&logo=react&logoColor=111111)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Unit%20Suite-1075%20passing-22C55E?style=for-the-badge)](tests/)

**Built for labs, internal security teams, and authorized engagements only.**

</div>

---

## What ARES Is

ARES turns a red-team or security-validation engagement into a structured,
auditable workflow:

1. Create a campaign.
2. Define explicit scope.
3. Select modules from the catalog.
4. Validate parameters with dry-run mode.
5. Execute authorized checks.
6. Store evidence and credentials safely.
7. Review findings, graph data, and OPSEC risk.
8. Generate branded reports.
9. Clean up test campaigns from the dashboard.

ARES is designed for the part of an engagement where authorization already
exists and the operator needs discipline, repeatability, reporting, and guardrails.

## What ARES Is Not

ARES is not:

- A C2 framework.
- An implant or beacon framework.
- A phishing framework.
- An initial-access toolkit.
- A tool for testing systems without written authorization.

Do not use ARES against systems you do not own or have explicit permission to
assess.

---

## Why It Exists

Offensive security work can become messy fast: scattered scripts, loose notes,
untracked evidence, unclear scope, repeated manual validation, and reports that
take longer than the test.

ARES focuses on the operational layer:

| Problem | ARES Approach |
| --- | --- |
| "What campaign is this finding from?" | Campaign-scoped storage and reports. |
| "Can this module run safely?" | Parameter validation, dry-run mode, OPSEC levels. |
| "Are we inside scope?" | Scope-first campaign model and backend validation. |
| "Where did this credential come from?" | Encrypted credential vault and campaign audit trail. |
| "How do we explain results?" | MITRE-aware findings and branded report generation. |
| "How do we avoid UI clutter?" | Campaign and API-key delete flows with backend cleanup. |
| "How do we test the app after changes?" | Local validation lab script. |

---

## Core Features

### Operator Dashboard

The React dashboard is served at:

```text
http://localhost:8080/dashboard
```

Dashboard areas:

| Page | Purpose |
| --- | --- |
| Overview | Health, telemetry, and campaign summary. |
| Campaigns | Create, inspect, compare, restore, dry-run, and delete campaigns. |
| Modules | Browse the module catalog and run backend-generated parameter forms. |
| Reports | Generate, list, and download authenticated campaign reports. |
| Graph | Review graph data, attack paths, and BloodHound ingest. |
| Templates | Generate repeatable execution plans. |
| Strategy | Start or review authorized goal-based planning. |
| Security | Change password, manage API keys, review audit and users. |
| EDR/OPSEC | Record bypass outcomes and review EDR/OPSEC telemetry. |
| Live | Watch campaign WebSocket events. |

See [docs/dashboard-guide.md](docs/dashboard-guide.md).

### Campaign System

- Explicit campaign scope.
- Campaign-specific findings, hosts, credentials, loot, reports, and graph data.
- Team-lead-only campaign deletion for lab cleanup.
- Vault restore after restart.
- Campaign diff and CVSS summary.

### Module Orchestration

- 60+ built-in modules across AD, Windows, Linux, cloud, network, credential,
  lateral movement, EDR/OPSEC, exfil exposure checks, persistence review, and AI
  planning.
- Backend-driven module parameter schema.
- Dry-run default in the dashboard.
- OPSEC levels for module risk.
- MITRE ATT&CK metadata for reporting.

See [docs/modules.md](docs/modules.md).

### Security Controls

- JWT access tokens with refresh-token rotation.
- Token revocation on logout.
- API key lifecycle with revoked-key removal from dashboard lists.
- RBAC roles: team lead, operator, recon, reporter.
- Encrypted data handling for sensitive credential material.
- Backend validation for scope, params, paths, and auth.
- Rate limiting for sensitive flows.
- Security headers and audit visibility.

See [docs/security-model.md](docs/security-model.md).

### Reporting

- HTML, Markdown, and JSON report output.
- PDF output when optional PDF dependencies are installed.
- ARES branding in generated reports.
- Findings, evidence, severity, timeline, and remediation-oriented sections.
- Authenticated report download through the dashboard.

### Validation Lab

ARES includes a local validation harness for checking the app after changes.

It validates:

- Health endpoint.
- Login and current profile.
- Campaign input validation.
- Local campaign create/list/delete.
- Module dry-run validation.
- Module API parameter validation.
- Report generation and listing.
- API key create/list/delete/list-after-delete.

See [docs/validation-lab.md](docs/validation-lab.md).

---

## Quickstart

### 1. Configure Required Secrets

PowerShell:

```powershell
$env:ARES_SECRET_KEY="local-dev-secret-key-32-chars-minimum!!"
$env:ARES_ENCRYPTION_KEY="local-dev-encryption-key-32-chars!!"
$env:ARES_DEFAULT_ADMIN_PASSWORD="ChangeMe123!Secure"
```

Bash:

```bash
export ARES_SECRET_KEY="local-dev-secret-key-32-chars-minimum!!"
export ARES_ENCRYPTION_KEY="local-dev-encryption-key-32-chars!!"
export ARES_DEFAULT_ADMIN_PASSWORD="ChangeMe123!Secure"
```

For production, use generated high-entropy values and rotate the bootstrap
admin password immediately after first login.

### 2. Start the API and Dashboard

From an installed package:

```bash
ares-api
```

From this repository on Windows:

```powershell
.\.venv\Scripts\ares-api.exe
```

Expected startup:

```text
ARES API v6.0.0 started
db_ready
engine_loaded_modules
```

Open:

```text
http://localhost:8080/dashboard
```

### 3. Check Health

```powershell
Invoke-RestMethod http://localhost:8080/health
```

Expected:

```text
status version db
------ ------- --
ok     6.0.0   connected
```

### 4. Run the Local Validation Lab

```powershell
$env:ARES_LAB_PASSWORD="ChangeMe123!Secure"
.\scripts\run_validation_lab.ps1
```

Expected ending:

```text
Validation lab passed.
```

---

## Developer Setup

Backend:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/unit -q
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit -q --tb=short --timeout=60 --timeout-method=thread
```

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Production build assets are served by FastAPI from `frontend/dist` at
`/dashboard`.

---

## Module Ecosystem

ARES modules are grouped by operational purpose:

| Category | Examples | Purpose |
| --- | --- | --- |
| Active Directory | `ad.enum_users`, `ad.kerberoast`, `ad.adcs` | Domain enumeration and authorized AD path validation. |
| Credential | `credential.crack`, `credential.pass_spray` | Credential workflow and offline validation. |
| Lateral | `lateral.winrm`, `lateral.wmiexec`, `lateral.psexec` | Approved lateral movement validation. |
| Windows | `windows.registry_enum`, `windows.uac_bypass` | Windows endpoint posture review. |
| Linux | `linux.kernel_suggester`, `linux.container` | Linux and container posture review. |
| Cloud | `cloud.aws`, `cloud.azure`, `cloud.gcp` | Cloud identity and control-plane review. |
| Network | `network.dns_enum`, `network.http_fingerprint` | Network and service discovery inside scope. |
| EDR/OPSEC | `edr.bypass_adaptive`, `opsec.coverage_predictor` | Defensive visibility and OPSEC decision support. |
| AI | `ai.autonomous_planner` | Goal-based planning from campaign context. |

High-noise modules require careful authorization and should be tested first in
dry-run mode.

---

## Architecture

```text
Browser Dashboard
       |
       v
FastAPI Server  ->  RBAC, auth, validation, rate limits
       |
       v
ARES Engine     ->  module registry, execution context, OPSEC checks
       |
       v
Modules         ->  AD, cloud, network, credential, EDR, reporting
       |
       v
Database        ->  campaigns, findings, vault records, API keys, audit data
```

Important design boundaries:

- The frontend improves UX but does not replace backend enforcement.
- Module forms are generated from backend metadata.
- Sensitive data stays behind authentication.
- Reports require authenticated download through the dashboard or API.
- Local validation flows use localhost by default.

See [docs/architecture.md](docs/architecture.md) and
[docs/engine_design.md](docs/engine_design.md).

---

## Documentation

| Document | Description |
| --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | First engagement walkthrough. |
| [docs/dashboard-guide.md](docs/dashboard-guide.md) | Dashboard page-by-page guide. |
| [docs/modules.md](docs/modules.md) | Module catalog and safe workflows. |
| [docs/api-reference.md](docs/api-reference.md) | API endpoints and request/response examples. |
| [docs/security-model.md](docs/security-model.md) | Security controls and threat model. |
| [docs/validation-lab.md](docs/validation-lab.md) | Local validation harness. |
| [docs/module-development.md](docs/module-development.md) | Build new modules. |
| [docs/module_sdk.md](docs/module_sdk.md) | Module SDK reference. |
| [docs/github-publish-guide.md](docs/github-publish-guide.md) | GitHub push and release checklist. |
| [docs/community-posts.md](docs/community-posts.md) | Facebook, Discord, and release announcement drafts. |

---

## Project Status

Current local verification:

```text
1075 unit tests passed
npm run build passed
validation lab passed
```

Runtime features confirmed locally:

- Dashboard loads at `/dashboard`.
- Health endpoint returns connected DB.
- Login, password change, API key lifecycle, and campaign cleanup work.
- Report generation and authenticated download work.
- Campaign delete removes stored child data and updates the UI immediately.

---

## Responsible Use

ARES is dual-use software. Use it only for:

- Owned lab environments.
- Internal security validation.
- Authorized red-team engagements.
- Training environments with permission.

Do not use ARES for unauthorized access, persistence, data theft, or testing
systems outside approved scope.

If you discover a security issue in ARES, follow [SECURITY.md](SECURITY.md).

---

## Contributing

Contributions are welcome when they improve safety, clarity, module quality,
operator experience, tests, documentation, or defensive validation workflows.

Start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/module-development.md](docs/module-development.md)
- [docs/module_sdk.md](docs/module_sdk.md)

Before opening a PR:

```bash
pytest tests/unit -q
cd frontend && npm run build
```

Do not commit `.env`, `.venv`, local databases, reports with real client data,
API keys, tokens, or screenshots that expose secrets.

---

## License

ARES is released under the [MIT License](LICENSE).

---

<div align="center">

**ARES - scoped, auditable, OPSEC-aware red-team engagement automation.**

</div>
