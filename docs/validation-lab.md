# ARES Local Validation Lab

The validation lab exercises safe API workflows through the same public origin
used by the browser. It does not attack external systems and never reads or
prints the HttpOnly refresh cookie.

## What It Checks

- CSRF bootstrap, cookie-aware login, `/auth/me`, and conclusive logout.
- Rejection of unsafe campaign input.
- Local campaign create, list, dry-run validation, report, and deletion flows.
- API-key create, list, delete, and list-after-delete behavior.

The lab retains the access token only in process memory. It does not accept a
password or token on the command line, and it does not use refresh JSON,
headers, query parameters, or browser-readable storage.

## Supported Local Flow

Use the Vite public origin for both the browser origin and the lab base URL.
Vite proxies HTTP API and WebSocket traffic to the backend.

Start the backend with the matching development policy:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:ARES_SECRET_KEY = -join ($bytes | ForEach-Object { $_.ToString("x2") })
$env:ARES_ENCRYPTION_KEY = .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ARES_DEFAULT_ADMIN_PASSWORD = "replace-with-your-own-strong-admin-password"
$env:ARES_DEBUG = "true"
$env:ARES_BROWSER_ORIGIN = "http://127.0.0.1:5173"
.\.venv\Scripts\ares-api.exe
```

Start Vite in another terminal:

```powershell
Set-Location .\frontend
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Then run the lab from a third terminal:

```powershell
$env:ARES_LAB_PASSWORD = "replace-with-your-current-admin-password"
.\scripts\run_validation_lab.ps1 `
  -BaseUrl "http://127.0.0.1:5173" `
  -BrowserOrigin "http://127.0.0.1:5173"
```

If `ARES_LAB_PASSWORD` and `ARES_DEFAULT_ADMIN_PASSWORD` are absent, the lab
uses a hidden interactive prompt. `ARES_DEFAULT_ADMIN_PASSWORD` creates only
the first account in an empty database; changing it later does not reset an
existing account.

The wrapper preserves the Python process exit status. It passes the explicit
browser origin but never forwards passwords or tokens in process arguments.

## Authentication Boundary

The lab performs these steps internally:

1. `GET /auth/csrf` with the exact configured `Origin`.
2. Retain the readable CSRF cookie in a private per-client cookie jar.
3. `POST /auth/token` with the username/password form, the same cookie jar,
   exact `Origin`, and matching `X-ARES-CSRF`.
4. Keep the returned access token in memory for the protected validation calls.
5. Use the newest readable CSRF cookie and the same jar for `POST /auth/logout`.

The login JSON contains no refresh token. The private jar carries the refresh
cookie ambiently; operators must not inspect, extract, serialize, or display
it.

Direct cross-origin backend login is unsupported. The public base URL and
browser origin must be canonical and identical. Plain HTTP is accepted only
for the fixed loopback Vite origins. An explicitly authorized remote lab must
use one exact HTTPS origin and `--allow-remote`; redirects on authentication
requests are rejected.

## Direct Python

```powershell
$env:ARES_LAB_PASSWORD = "your-current-admin-password"
.\.venv\Scripts\python.exe .\scripts\validation_lab.py `
  --base-url "http://127.0.0.1:5173" `
  --browser-origin "http://127.0.0.1:5173" `
  --username admin
```

The browser origin may instead come from `ARES_LAB_BROWSER_ORIGIN`, then
`ARES_BROWSER_ORIGIN`. Absence is rejected; it is never inferred from the base
URL.
