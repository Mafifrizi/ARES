# ARES Local Validation Lab

This lab is a safe local harness for checking ARES after UI or backend changes.
It does not attack external systems. By default it only talks to `localhost:8080`.

## What It Checks

- API health is online.
- Login and `/auth/me` work.
- Bad campaign target input is rejected with `422`.
- A local dummy campaign can be created, listed, deleted, and verified removed.
- Plan dry-run catches missing module params without touching a target.
- Direct module run rejects missing params with `422`.
- API key create, list, delete, and list-after-delete work.
- HTML report generation and report listing work.

## Run

Start ARES first:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:ARES_SECRET_KEY = -join ($bytes | ForEach-Object { $_.ToString("x2") })
$env:ARES_ENCRYPTION_KEY = .\.venv\Scripts\python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:ARES_DEFAULT_ADMIN_PASSWORD = "replace-with-your-own-strong-admin-password"
.\.venv\Scripts\ares-api.exe
```

In another PowerShell:

```powershell
$env:ARES_LAB_PASSWORD="replace-with-your-own-strong-admin-password"
.\scripts\run_validation_lab.ps1
```

If the admin password has been changed, put the current password in
`ARES_LAB_PASSWORD`.

`ARES_DEFAULT_ADMIN_PASSWORD` is used only when ARES creates the first
`admin` account in an empty user table. Changing that environment variable
after a local admin already exists does not reset the password used by this
lab.

## Direct Python

```powershell
$env:ARES_LAB_PASSWORD="your-current-admin-password"
.\.venv\Scripts\python.exe .\scripts\validation_lab.py --base-url http://localhost:8080 --username admin
```

## Safety Guard

The script refuses non-localhost URLs by default. For an explicitly authorized
lab host only:

```powershell
.\.venv\Scripts\python.exe .\scripts\validation_lab.py --base-url http://127.0.0.1:8080
```

Use `--allow-remote` only for a lab you own or are explicitly authorized to test.
