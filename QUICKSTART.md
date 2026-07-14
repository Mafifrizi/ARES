# ARES Quickstart

ARES is an operator dashboard and automation framework for authorized red-team
validation, lab workflows, campaign orchestration, module execution, telemetry,
reporting, RBAC, and security checks.

Use it only on systems you own or have written permission to assess.

## Universal first-run workflow

This is the supported path from a fresh clone to a first campaign report. It is
not AD-specific. AD/Kerberos, cloud, Windows, Linux, credential, network, and
other module families all start with the same campaign, module, findings, and
report workflow. Module-specific differences begin at module selection,
required optional extras/tools, and parameter values.

### A. Prerequisites

- Git.
- Python 3.12.x for the recommended/tested release path.
- Node.js/npm for dashboard development mode.
- Normal non-Administrator PowerShell on Windows.
- Written authorization, an owned lab, or an approved engagement scope.

### B. Clone and enter repo

Windows PowerShell:

```powershell
git clone https://github.com/Mafifrizi/ARES.git
Set-Location .\ARES
```

Linux/macOS:

```bash
git clone https://github.com/Mafifrizi/ARES.git
cd ARES
```

### C. Create virtualenv and install ARES baseline

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev,pdf]"
```

Linux/macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev,pdf]"
```

`dev,pdf` is the local dashboard/reporting baseline. The base dashboard does
not require every optional module family. Install optional extras only when you
need that module family.

Optional extras examples:

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[ad]"
.\.venv\Scripts\python.exe -m pip install -e ".[ad-support]"
.\.venv\Scripts\python.exe -m pip install -e ".[cloud]"
.\.venv\Scripts\python.exe -m pip install -e ".[windows]"
.\.venv\Scripts\python.exe -m pip install -e ".[full]"
```

Linux/macOS:

```bash
python -m pip install -e ".[ad]"
python -m pip install -e ".[ad-support]"
python -m pip install -e ".[cloud]"
python -m pip install -e ".[windows]"
python -m pip install -e ".[full]"
```

For AD modules, use `.[ad]` for a normal full AD install. If `ares doctor`
already reports `impacket` as importable from a source/local install, use
`.[ad-support]` to install the remaining direct AD support libraries
(`pyasn1`, `pyasn1_modules`, `ldap3`, and `httpx_ntlm`) without forcing another
PyPI Impacket wheel install. After installing AD dependencies, restart
`ares dashboard dev --no-reload`, rerun `ares doctor --pdf-smoke`, and confirm
`pyasn1`, `pyasn1_modules`, `ldap3`, and `httpx_ntlm` are no longer missing.

### D. Install frontend dependencies

Windows PowerShell:

```powershell
Set-Location frontend
& "C:\Program Files\nodejs\npm.cmd" ci
Set-Location ..
```

Linux/macOS:

```bash
cd frontend
npm ci
cd ..
```

`ares dashboard dev --install` can run `npm ci` for you when
`frontend/node_modules` is missing.

### E. Configure required secrets

ARES requires these values before the first dashboard login:

| Variable | Purpose |
| --- | --- |
| `ARES_SECRET_KEY` | Signs API sessions and tokens. Generate a random high-entropy value. |
| `ARES_ENCRYPTION_KEY` | Encrypts sensitive stored data such as vault/checkpoint material. Keep it stable and backed up. |
| `ARES_DEFAULT_ADMIN_PASSWORD` | Bootstrap password for the first `admin` account only when the user table is empty. |

Windows PowerShell:

```powershell
$env:ARES_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
$env:ARES_ENCRYPTION_KEY = .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ARES_DEFAULT_ADMIN_PASSWORD = "replace-with-your-own-strong-admin-password"
```

Linux/macOS:

```bash
export ARES_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ARES_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export ARES_DEFAULT_ADMIN_PASSWORD="replace-with-your-own-strong-admin-password"
```

For repeated local use, copy `.env.example` to `.env` and fill these values
there instead of setting session variables each time.

Important:

- The first admin bootstrap password comes from `ARES_DEFAULT_ADMIN_PASSWORD`
  in the current environment or `.env` file.
- Changing `ARES_DEFAULT_ADMIN_PASSWORD` after `admin` already exists does not
  reset that user's password.
- Change the admin password after first login.
- Do not commit, print, record, or share secrets.
- ARES API keys created later in the dashboard are separate from these startup
  secrets and from LLM provider keys.

### F. Run doctor/pdf smoke before starting dashboard

Windows PowerShell:

```powershell
$env:ARES_PDF_BROWSER = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
.\.venv\Scripts\ares.exe doctor --pdf-smoke
```

`ARES_PDF_BROWSER` points ARES PDF export to Microsoft Edge for the current
PowerShell session. This is recommended on Windows when WeasyPrint native
GTK/Pango libraries are not installed. Use normal non-Administrator
PowerShell.

Expected successful fallback lines include:

```text
[OK] PDF ARES_PDF_BROWSER ... exists=True
[OK] PDF browser detected ... msedge.exe
[OK] PDF smoke ... bytes=...
```

A WeasyPrint GTK/Pango warning on Windows is acceptable when Edge/Chrome
fallback and PDF smoke succeed. Importable Impacket from a source/local install
can show OK with an unknown version. Missing optional module families/tools may
warn until installed. Optional hashcat, john, cloud, Windows, or AD warnings do
not block base dashboard/reporting.

Linux/macOS:

```bash
ares doctor --pdf-smoke
```

### G. Start dashboard

Windows PowerShell:

```powershell
.\.venv\Scripts\ares.exe dashboard dev --no-reload
```

Linux/macOS:

```bash
ares dashboard dev --no-reload
```

URLs:

- Backend API: `http://127.0.0.1:8080`
- Dashboard: `http://127.0.0.1:5173/dashboard/`

The `dashboard dev` command is the normal local launcher. `--no-reload` is
recommended for stable demos and recording.

Useful launcher options:

- `--no-open`: print the URL without opening a browser.
- `--no-reload`: start uvicorn without reload.
- `--install`: run `npm ci` in `frontend/` if `node_modules` is missing.
- `--api-host` / `--api-port`: change the backend bind address.
- `--ui-host` / `--ui-port`: change the Vite bind address.

Manual fallback for troubleshooting:

Terminal 1:

```powershell
Set-Location "<ARES repo root>"
.\.venv\Scripts\python.exe -m uvicorn ares.api.server:app --host 127.0.0.1 --port 8080 --reload
```

Terminal 2:

```powershell
Set-Location "<ARES repo root>\frontend"
& "C:\Program Files\nodejs\npm.cmd" run dev -- --host 127.0.0.1 --port 5173
```

Then open:

```text
http://127.0.0.1:5173/dashboard/
```

### H. Login

- Username: `admin`
- Password: value of `ARES_DEFAULT_ADMIN_PASSWORD`

The launcher prints the username and dashboard URL, but it does not print the
password value. Change the admin password from `Security` after first login.
Do not show passwords in videos or screenshots.

### I. Create users and assign roles

The first account is created automatically:

- Username: `admin`
- Role: `team_lead`
- Password source: `ARES_DEFAULT_ADMIN_PASSWORD`

The dashboard `Security` page lists users for review, but the current release
does not include a role editor. Additional users are created by a `team_lead`
through `POST /auth/register`, and the role is assigned at account creation.

Valid roles:

| Role | Purpose |
| --- | --- |
| `team_lead` | Full local admin/operator lead. Can create users, delete campaigns, view security audit, authorize restricted workflows, and run normal operator work. |
| `operator` | Daily operator. Can run normal campaign/module/report workflows. |
| `recon` | Read-heavy recon identity. Main dashboard execution endpoints remain operator-gated. |
| `reporter` | Read-only reporting and review. No module execution or user administration. |

PowerShell example:

```powershell
$token = (Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/auth/token `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin&password=YOUR_CURRENT_ADMIN_PASSWORD").access_token

$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/auth/register `
  -Headers $headers `
  -ContentType "application/json" `
  -Body (@{
    username = "alice"
    password = "StrongPass1!"
    role = "operator"
  } | ConvertTo-Json)
```

Passwords must be at least 12 characters and include uppercase, lowercase,
number, and special-character content.

### J. Create and use an ARES API key

API keys are created from the `Security` page after login. They are ARES
automation credentials, not OpenAI, Anthropic, or Ollama keys.

When you create a key:

- The `Save your key` modal shows the full secret once.
- After the modal closes, only prefix/metadata are visible.
- Store the secret securely outside ARES if you need it later.
- Scripts use the `X-API-Key` header.

Example against a real authenticated endpoint that accepts API keys:

```powershell
$headers = @{ "X-API-Key" = "YOUR_ARES_API_KEY" }

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8080/auth/me" `
  -Headers $headers
```

### K. Universal campaign workflow

1. Open `Campaigns`.
2. Create a campaign.
3. Define campaign name, client, targets, and scope CIDRs.
4. Open `Modules`.
5. Choose any module from the catalog.
6. Select the campaign.
7. Fill backend-generated parameters.
8. Run dry-run first where supported.
9. Execute only inside authorized scope.
10. Review module output in `Results`.
11. Review persisted findings in `Campaigns` / `Findings` or the relevant
    findings view.
12. Open `Reports`.
13. Generate JSON, PDF, HTML, or Markdown.
14. Open `Library`.
15. Download artifacts.
16. Delete one artifact or use `Delete all` / Clear library.

Module-specific differences begin at module selection, optional extras/tools,
and parameter values. AD/Kerberos, cloud, network, credential, Windows, Linux,
and other modules follow the same campaign/module/report flow.

### L. Reports and Library

Open `Reports`:

1. Select a campaign.
2. Generate `json`.
3. Switch to `Library` and download the JSON artifact.
4. Generate `pdf`.
5. Switch to `Library` and download the PDF artifact.
6. Generate `html` or `markdown` where supported.
7. Use a row's `Delete` action to remove one artifact after confirming.
8. Use `Delete all` / Clear library to remove the campaign's generated report
   artifacts after confirming.

Report evidence is redacted by default. Raw hashes, passwords, tokens, and
other secrets should appear only in authorized internal review paths. Do not
publish them in public demos or shared reports.

Successful report library delete actions update rows and artifact counts. When
no reports remain, the Library shows `No reports generated for this campaign
yet.`

### M. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `ares` command not found on Windows | Use `.\.venv\Scripts\ares.exe ...` from the repository root. |
| `frontend/node_modules` missing | Run `npm ci` in `frontend/`, or start with `ares dashboard dev --install`. |
| PDF smoke warning on Windows | Use normal non-Administrator PowerShell, set `$env:ARES_PDF_BROWSER = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"`, then run `.\.venv\Scripts\ares.exe doctor --pdf-smoke`. |
| Optional module dependency warning | Install the relevant extra only when that module family is needed, for example `.[ad]`, `.[cloud]`, `.[windows]`, or `.[full]`. For source/local Impacket AD setups, use `.[ad-support]` for the remaining direct AD support libraries. |
| Impacket source/local install version unknown | OK if Impacket is importable; install `.[ad-support]` if `pyasn1`, `pyasn1_modules`, `ldap3`, or `httpx_ntlm` still warn. Missing or too-old Impacket still warns. |
| `Invalid credentials` | Use the current admin password. Updating `ARES_DEFAULT_ADMIN_PASSWORD` after admin exists does not reset that password. |
| `Target is not in campaign scope` | Add the target CIDR to the campaign scope, for example `127.0.0.1/32` for local testing. |
| Report direct URL returns `401` | Use the authenticated dashboard Download button. |
| Pytest on Windows fails before tests with temp ACL errors | Developer validation only: use a writable temp root or fix the stale `%TEMP%\pytest-of-<user>` permissions. This is not part of normal first-run use. |

## Optional planning and module notes

### Templates

Open `Templates` when you want a repeatable plan. Templates produce
deterministic plan stages, do not call an LLM, and do not execute modules by
themselves.

### Strategy and AI planning

Strategy is for goal-based planning against an existing campaign. The default
strategy path expects an LLM provider key unless you configure a local backend.
ARES API keys from the `Security` page are not LLM keys.

Common LLM environment variables:

```bash
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
```

Use Strategy only after a campaign exists, scope is correct, authorization
notes are clear, and the selected LLM backend is configured.

### Public SDK

Use the public SDK import path for custom modules:

```python
from ares.sdk import BaseModule, ExecutionContext, Finding, ModuleResult
```

`ares.modules.sdk` remains as a compatibility shim, but new code should use
`ares.sdk`.

See:

- `docs/module-development.md`
- `docs/module_sdk.md`
- `docs/examples/example_http_enum.py`

### Validation lab

Run the validation lab after changing API or dashboard behavior:

```powershell
$env:ARES_LAB_PASSWORD="YOUR_CURRENT_ADMIN_PASSWORD"
.\scripts\run_validation_lab.ps1
```

The lab checks login, profile, campaign validation, dry-run validation,
reports, and API key lifecycle.

## Safety reminder

ARES is intended for authorized security testing, lab use, and defensive
validation only.
