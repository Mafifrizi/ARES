# Changelog

All notable changes to ARES are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

---

## [6.0.0] — 2026-03-21

### The story behind v6

v5 worked. It got the job done — enumerate, kerberoast, maybe dcsync if you were lucky.
But it was a script runner with a CLI bolted on. Every engagement looked the same.
Every operator had to make the same manual decisions. And when defenders got better,
the static playbooks started failing.

Three things forced the rewrite:

**Defenders got smarter.** By 2024, mature EDR deployments were catching static sequences
reliably. A tool that runs the same order every time is a known signature. OPSEC needed
to be baked into every layer — not an afterthought.

**Engagements got more complex.** Multi-cloud + hybrid AD + container environments mean
an operator can't mentally track all the attack paths anymore. We needed something that
could hold the state of an engagement and make decisions based on what had already been
tried and failed.

**The credential vault gap.** Every red team tool treats credentials as ephemeral.
Harvest, use, forget. We wanted persistence — a vault that accumulates across the
engagement, scores by privilege, and automatically feeds downstream modules.

v6 is the answer to those three problems. 60 modules. A goal-based engine. Scope
enforcement that runs in Python so LLM hallucinations can't bypass it. An encrypted vault.
An AI planner that learns from each round. And a 7-session security audit that found
and fixed 20+ issues before shipping.

It's still operator-directed. Every dangerous module requires explicit authorization.
But now there's infrastructure under you instead of just a script.

---

### Added

**Core engine**
- 60 attack modules across 11 categories
- `StrategyEngine` — multi-round autonomous engagement loop with detection spike protection
- `ConstitutionEnforcer` — Python-layer safety that LLM prompts cannot bypass
- `TargetStateMap` — per-host memory across rounds (prevents re-running failed techniques)
- `OutcomeKnowledgeBase` — quality-weighted learning from module results

**AI & OPSEC**
- `ai.autonomous_planner` — LLM-powered attack chain (Claude / OpenAI / Ollama)
- Multi-LLM consensus mode — two LLMs agree = higher confidence plan
- Adversarial simulation — blue team LLM predicts detection timeline for attack plan
- `edr.bypass_adaptive` — EDR vendor detection → ranked techniques + live probes + BYOVD
- `opsec.coverage_predictor` — detection probability with SOC shift model and SIEM correlation
- Dwell time decay — longer undetected = lower estimated detection risk
- Pre-execution prediction — score *before* a plan runs, not after

**Cloud**
- `cloud.identity_federation_abuse` — Golden SAML, SAML/OIDC cross-cloud pivot, GCP WIF
- Azure Managed Identity enumeration — zero-credential attack path via MI + high-privilege roles
- GCP Workload Identity Federation — GitHub Actions → GCP service account impersonation
- Azure B2B cross-tenant enumeration — Midnight Blizzard-style pivot detection
- Token lifetime abuse detection — CAE status, legacy auth, refresh token policy

**Security (audit results)**
- Engine-level scope pre-check before any module executes
- DNS-resolving scope guard — fails closed if hostname can't resolve
- bcrypt DoS protection on all password fields + `/auth/token` form
- SQL injection mitigated in `lateral.mssql` (safe_cmd escaping + MSSQLParams schema)
- Shell injection fixed in `exfil.secrets_scan` and `exfil.staged_collection` (shlex.quote)
- TOCTOU fixed in `windows.lsass_dump` and `windows.dpapi` (mkstemp)
- `marketplace/installer.py` — SHA-256 hash verification before file install
- `worker/cluster.py` — credential params redacted before Redis HSET
- GCP project_id pattern validation (blocks path traversal)
- `ALWAYS_REQUIRE_AUTH` modules require `team_lead` role at API level
- Concurrent engagement limit (`ARES_MAX_ENGAGEMENTS`, default 3)
- Campaign ownership check on `/strategy/engage`

**Infrastructure**
- `POST /strategy/engage` API — start autonomous engagement with full RBAC
- `GET /strategy/active` — query running engagements and available slots
- `POST /edr/bypass/report` — operator reports bypass outcomes from the field
- Cross-session bypass learning via DB persistence (90-day rolling window)
- `bypass_outcomes` DB table — historical success rates per technique × EDR vendor
- Pydantic validation for all 60 modules (up from 10)
- `PlanValidator` — catches LLM hallucinated module IDs before engine execution
- Round narrative injection — LLM sees history of what failed per host
- Credential actionability formatting — LLM knows which modules to use per credential type

**Developer experience**
- `ares doctor` with exact fix commands per failure (pyenv, apt, brew, pip)
- SHA-pinned nginx image in `docker-compose.prod.yml`
- Pre-commit config with freeze instructions for full supply-chain security
- QUICKSTART.md — 30-minute lab guide with GOAD setup
- CONTRIBUTING.md, SECURITY.md, MODULE_GUIDE.md

### Changed

- `[full]` extra now includes `[windows]` (pypykatz for lsass_dump)
- `[ad]` extra now includes `httpx-ntlm` for ADCS ESC1 HTTP enrollment
- `[cloud]` extra now includes `msal` for Azure AD device code flow
- Coverage threshold raised to 85% (roadmap: 90%)
- CI: `pip freeze` auto-generates pinned lock file on push to `main`

### v5 → v6 migration

v5 used a single fixed salt for all encryption. v6 uses per-record PBKDF2-SHA256 (100k iterations).
Existing v5 data is readable via `ARES_LEGACY_SALT` env var — set this to your v5 salt before migrating.

See `migrations/` for Alembic migration scripts.

---

*See git history for v5 changes.*
