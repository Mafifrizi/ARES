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
$env:ARES_SECRET_KEY="local-dev-secret-key-32-chars-minimum!!"
$env:ARES_ENCRYPTION_KEY="local-dev-encryption-key-32-chars!!"
$env:ARES_DEFAULT_ADMIN_PASSWORD="ChangeMe123!Secure"
.\.venv\Scripts\ares-api.exe
```

In another PowerShell:

```powershell
$env:ARES_LAB_PASSWORD="ChangeMe123!Secure"
.\scripts\run_validation_lab.ps1
```

If the admin password has been changed, put the current password in
`ARES_LAB_PASSWORD`.

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
