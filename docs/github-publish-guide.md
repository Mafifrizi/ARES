# GitHub Publishing Guide

This guide prepares ARES for a clean GitHub push.

## Before You Push

Do not publish secrets or local runtime data.

Already ignored by `.gitignore`:

- `.env`
- `.venv/`
- `ares.db`
- `ares.db-shm`
- `ares.db-wal`
- `logs/`
- `evidence/`
- `frontend/dist/`
- `node_modules/`

Still check manually:

- No real passwords in docs, screenshots, reports, or examples.
- No API keys.
- No access tokens.
- No customer names or target IPs.
- No private report output.
- No copied browser session data.

Rotate local credentials before publishing screenshots or demo material.

## Suggested Public Repo Structure

Keep these files visible:

- `README.md` - public landing page.
- `QUICKSTART.md` - first run guide.
- `SECURITY.md` - responsible use and reporting.
- `CONTRIBUTING.md` - contribution rules.
- `CHANGELOG.md` - release history.
- `docs/modules.md` - operator module guide.
- `docs/dashboard-guide.md` - dashboard walkthrough.
- `docs/api-reference.md` - API docs.
- `docs/security-model.md` - security model.
- `docs/validation-lab.md` - local validation lab.
- `docs/community-posts.md` - launch copy for Facebook and Discord.

## Initialize Git

If this folder is not a git repo yet:

```powershell
cd C:\Users\ASUS\ARES
git init
git branch -M main
git status
```

Review what will be committed:

```powershell
git status --short
git diff -- README.md QUICKSTART.md docs
```

Stage the project:

```powershell
git add .gitignore README.md QUICKSTART.md SECURITY.md CONTRIBUTING.md CHANGELOG.md pyproject.toml ares docs scripts tests frontend docker migrations example_modules
git status --short
```

Commit:

```powershell
git commit -m "docs: prepare ARES public launch kit"
```

## Connect to GitHub

Create an empty GitHub repository first. Do not initialize it with a README if
you already committed locally.

Then:

```powershell
git remote add origin https://github.com/Mafifrizi/ARES.git
git push -u origin main
```

If `origin` already exists:

```powershell
git remote -v
git remote set-url origin https://github.com/Mafifrizi/ARES.git
git push -u origin main
```

## Recommended Release Notes

Title:

```text
ARES v6.0.0 - Dashboard, validation lab, and OPSEC-first red-team automation
```

Short description:

```text
ARES v6 is an authorized red-team engagement framework with a FastAPI backend,
React dashboard, encrypted credential vault, campaign-scoped execution, module
catalog, report generation, API-key management, validation lab, and OPSEC-aware
controls.
```

Highlights:

- React dashboard served at `/dashboard`.
- Campaign, module, report, graph, strategy, security, EDR/OPSEC, and live views.
- 60+ built-in modules across AD, credential, lateral, Windows, Linux, cloud,
  network, exfil, persistence, OPSEC, and AI planning.
- Encrypted vault and token revocation.
- RBAC for team lead, operator, recon, and reporter workflows.
- Local validation lab for safe smoke testing.
- HTML, PDF, Markdown, and JSON report generation with ARES branding.
- Campaign delete flow for cleanup of lab/test campaigns.

Safety note:

```text
ARES is for authorized security testing only. Do not use it against systems you
do not own or have explicit written permission to assess.
```

## GitHub README Checklist

Before posting:

- Does the README explain what ARES is in the first screen?
- Does it say "authorized use only" clearly?
- Are screenshots free of secrets?
- Is the install/start command correct for Windows and Linux?
- Are docs links working?
- Does the module count say `60+` instead of a fragile exact number?
- Does the project explain what it is not? It is not malware, not a C2 implant,
  and not an initial-access tool.

## Suggested Repository Description

```text
ARES - authorized red-team engagement automation with dashboard, campaign scope,
module orchestration, OPSEC controls, encrypted vault, and reporting.
```

Suggested topics:

```text
red-team, security, fastapi, react, mitre-attack, active-directory, cloud-security,
opsec, reporting, defensive-validation
```

