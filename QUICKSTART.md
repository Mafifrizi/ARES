# ARES Quickstart

ARES is an operator dashboard and automation framework for authorized red-team validation, lab workflows, campaign orchestration, module execution, telemetry, reporting, RBAC, and security checks.

Use it only on systems you own or have written permission to assess.

## 1. Clone And Enter The Project

```bash
git clone https://github.com/Mafifrizi/ARES.git
cd ARES
```

## 2. Install The Local Environment

Linux/macOS:

```bash
bash scripts/setup.sh
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,pdf]"
```

Notes:

- The setup script is the Linux/macOS bootstrap path. On Windows, use the
  PowerShell commands above to create `.venv` and install the editable package.
- Some offensive-security integrations are optional. `ares doctor` will tell you which optional packages or native tools are missing for AD, cloud, container, or password-cracking workflows.
- PDF support uses WeasyPrint when available and has a local browser fallback in the API.

## 3. Configure Secrets

ARES requires three local environment values before the API starts.

These values are created by the operator or deployment owner. ARES does not provide shared public secrets.

### Linux/macOS

```bash
export ARES_SECRET_KEY="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"

export ARES_ENCRYPTION_KEY="$(python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"

export ARES_DEFAULT_ADMIN_PASSWORD="ChangeThisAdminPassword123!"
```

### Windows PowerShell

```powershell
$env:ARES_SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:ARES_ENCRYPTION_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ARES_DEFAULT_ADMIN_PASSWORD = "ChangeThisAdminPassword123!"
```

What each value does:

| Variable | Purpose | Keep Stable? |
| --- | --- | --- |
| `ARES_SECRET_KEY` | Signs API sessions and tokens. | Yes, for a deployed instance. Rotating it invalidates sessions. |
| `ARES_ENCRYPTION_KEY` | Encrypts sensitive local data such as credential vault material. | Yes. Losing or changing it can make existing encrypted data unreadable. |
| `ARES_DEFAULT_ADMIN_PASSWORD` | Password for the first bootstrap `admin` account when the user table is empty. | Change after first login. Updating this value later does not reset an existing admin. |

For repeated local use, copy `.env.example` to `.env`, fill these values once, and start ARES from the same project directory.

## 4. Start The API And Dashboard

```bash
ares dashboard dev
```

This starts the FastAPI backend and the Vite dashboard dev server in one
terminal. It prints:

- Backend API URL: `http://127.0.0.1:8080`
- Dashboard URL: `http://127.0.0.1:5173/dashboard/`
- Login username: `admin`
- Login password: value of `ARES_DEFAULT_ADMIN_PASSWORD` in `.env`

The launcher opens the dashboard by default and does not print the password
value. Use `ares dashboard dev --no-open` to print the URL without opening a
browser. If `frontend/node_modules` is missing, run:

```bash
ares dashboard dev --install
```

Manual fallback for troubleshooting:

Terminal 1:

```powershell
.\.venv\Scripts\python.exe -m uvicorn ares.api.server:app --host 127.0.0.1 --port 8080 --reload
```

Terminal 2:

```powershell
cd frontend
"C:\Program Files\nodejs\npm.cmd" run dev -- --host 127.0.0.1 --port 5173
```

Then open:

```text
http://127.0.0.1:5173/dashboard/
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

Expected result:

```json
{"status":"ok","version":"6.0.0","db":"connected"}
```

Login with:

- Username: `admin`
- Password: your `ARES_DEFAULT_ADMIN_PASSWORD`

Then change the admin password from the `Security` page.

The first `admin` user is created only when the user table is empty. If you
already have a local database, use the current admin password. Changing
`ARES_DEFAULT_ADMIN_PASSWORD` after the account exists will not update that
password. For disposable local data, recreate the local `ares.db`; otherwise,
change the password from the dashboard after login.

Local development reset warning: this deletes local dashboard data in
`ares.db`. Do not use it on real or shared deployments.

```powershell
New-Item -ItemType Directory -Force ".\_db_backup" | Out-Null
if (Test-Path ".\ares.db") {
  Copy-Item ".\ares.db" ".\_db_backup\ares.db.before-reset" -Force
}
Remove-Item ".\ares.db" -Force -ErrorAction SilentlyContinue
```

Dashboard shell:

- The left sidebar routes between Overview, Campaigns, Modules, Reports, Graph,
  Templates, Strategy, Security, EDR/OPSEC, and Live.
- The topbar menu button collapses or expands the sidebar.
- Topbar quick search navigates over currently loaded page names/routes,
  campaigns, modules, reports, and templates. It is not a backend global search
  over unloaded history.
- The notification bell is the only topbar status surface. Its badge counts
  unread notifications; opening the drawer marks visible items as read, and the
  drawer supports individual dismiss plus clear-all.
- The topbar also provides signed-in identity and logout.
- Current tabs are: Campaigns `List`/`Scope`/`Findings`, Modules
  `Catalog`/`Run Panel`/`Results`, Reports `Generate`/`Library`, Graph
  `Entities`/`Attack Paths`/`Ingest`, Templates `Templates`/`Plan Builder`,
  Strategy `Objective`/`Active`/`Result`, Security `Account`/`API Keys`/`Audit`,
  EDR/OPSEC `Knowledge Base`/`Report Outcome`, and Live `Stream`/`Buffer`.
  Overview has no variation tabs.

## 5. Create A Campaign

Open `Campaigns` and create a scoped campaign.

Example local demo values:

| Field | Example |
| --- | --- |
| Name | `ARES Local Finding Demo` |
| Client | `Internal` |
| Targets | `127.0.0.1` |
| Scope CIDRs | `127.0.0.1/32` |

Scope matters. Targeted modules will refuse to run if the target is outside the selected campaign scope.

## 6. Run A Module Safely

Open `Modules`:

1. Select the campaign.
2. Search for a module.
3. Fill the generated parameter fields.
4. Run with `Dry run` first when available.
5. Run live only when the target and scope are authorized.

The dashboard catalog loads the built-in module metadata from the backend.
Module IDs, names, categories, OPSEC labels, and parameter schemas come from
that catalog. High-noise or sensitive modules remain guarded by authorization
and confirmation checks; do not run destructive, credential, lateral movement,
exfiltration, persistence, or bypass workflows outside an approved lab or
engagement.

Port behavior is module-specific. Some modules require explicit ports because they fingerprint a service. Broader discovery belongs in enumeration modules such as port scanning, then the discovered services can be used by more specific modules.

## 7. Generate Reports

Open `Reports`:

1. Select a campaign.
2. Choose HTML, PDF, Markdown, or JSON.
3. Click `Generate`.
4. Use the dashboard `Download` button.

Do not open report file URLs directly in the browser address bar. Report downloads are authenticated, so direct unauthenticated URLs return `401`.

## 8. Use Templates

Open `Templates` when you want a repeatable plan.

Templates:

- Generate deterministic plan stages.
- Do not call an LLM.
- Do not execute modules by themselves.
- Are useful as a checklist before running campaign modules.

Typical flow:

1. Select a built-in template such as `internal_pentest`.
2. Optionally provide JSON parameters.
3. Click `Generate Plan`.
4. Review the returned stages and module IDs.
5. Execute approved modules manually from the campaign workflow.

## 9. Use Strategy And AI Planning

Strategy is for goal-based planning against an existing campaign.

The default strategy path expects an LLM provider key unless you configure a local backend. ARES API keys from the `Security` page are not LLM keys.

Common LLM environment variables:

```bash
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
```

Use Strategy only after:

- A campaign exists.
- Scope is correct.
- Authorization notes are clear.
- The required LLM provider key is configured, or a supported local backend is selected through the API.

## 10. API Keys In The Security Page

Dashboard API keys authenticate scripts and integrations to ARES itself.

Use them as:

```bash
curl http://localhost:8080/campaigns \
  -H "X-API-Key: ares_YOUR_KEY"
```

They are not OpenAI, Anthropic, or Ollama keys.

When you create a key, the dashboard opens the `Save your key` modal and shows
the full secret once. Use `Copy`; after a successful copy the button changes to
`Copied`. `Done` closes the modal and clears the in-memory new-key state. The
API key list shows metadata and a prefix only, so the full secret cannot be
retrieved later.

## 11. Roles

The first user is `admin` with the `team_lead` role.

| Role | Purpose |
| --- | --- |
| `team_lead` | Full local admin/operator lead. Can create users, delete campaigns, view security audit, and authorize higher-risk workflows. |
| `operator` | Daily operator. Can run normal campaign/module/report workflows. |
| `recon` | Read-heavy recon identity. Main dashboard execution endpoints remain operator-gated. |
| `reporter` | Read-only reporting and review. |

Create users through `POST /auth/register` with a team-lead token. See `docs/dashboard-guide.md` for a PowerShell example.

## 12. Doctor And Optional Dependencies

Run:

```bash
ares doctor
```

`ares doctor` checks Python, key dependencies, optional module integrations, native tools, network socket support, environment configuration, and the local database.

A yellow warning means an optional integration is missing. A red failure means a required dependency or configuration item needs attention.

Common examples:

| Message | Meaning |
| --- | --- |
| `impacket` missing or old | AD/SMB modules need the optional impacket dependency. |
| `pip-audit not installed` | Dependency audit is unavailable; core API can still start. |
| `hashcat not in PATH` | Password-cracking helpers cannot use hashcat until installed. |
| `.env configured` failed | Required environment values are missing. |

## 13. Public SDK

Use the public SDK import path for custom modules:

```python
from ares.sdk import BaseModule, ExecutionContext, Finding, ModuleResult
```

`ares.modules.sdk` remains as a compatibility shim, but new code should use `ares.sdk`.

See:

- `docs/module-development.md`
- `docs/module_sdk.md`
- `docs/examples/example_http_enum.py`

## 14. Validation Lab

Run the validation lab after changing API or dashboard behavior:

```powershell
$env:ARES_LAB_PASSWORD="YOUR_CURRENT_ADMIN_PASSWORD"
.\scripts\run_validation_lab.ps1
```

The lab checks login, profile, campaign validation, dry-run validation, reports, and API key lifecycle.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `ARES not configured` | Set `ARES_SECRET_KEY`, `ARES_ENCRYPTION_KEY`, and `ARES_DEFAULT_ADMIN_PASSWORD`. |
| `Invalid credentials` | Use the current admin password, not the placeholder or a newly changed `ARES_DEFAULT_ADMIN_PASSWORD` value after the admin already exists. |
| `Request failed with 422` | A required field is missing or a target/scope value is invalid. |
| `Target is not in campaign scope` | Add the target CIDR to the campaign scope, for example `127.0.0.1/32`. |
| `Global rate limit exceeded` | Wait briefly, then retry. Avoid repeatedly clicking actions while a request is pending. |
| Report direct URL returns `401` | Use the authenticated dashboard Download button. |
| Strategy does nothing useful | Confirm the campaign, authorization notes, and LLM provider key. |

## Safety Reminder

ARES is intended for authorized security testing, lab use, and defensive validation only.
