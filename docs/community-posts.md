# ARES Community Posting Kit

Use this file when posting ARES to Facebook groups, Discord servers, or a GitHub
release announcement. Keep the tone honest: this is an authorized red-team and
security validation tool, not a toy for attacking random systems.

## One-Line Pitch

ARES is an authorized red-team engagement framework with a dashboard, campaign
scope enforcement, module orchestration, encrypted vault, OPSEC controls, and
report generation.

## Short Description

ARES helps operators turn an authorized engagement into a structured workflow:
create a campaign, define scope, run modules in dry-run first, review findings,
track risk, generate reports, and clean up validation data from the dashboard.

It includes a FastAPI backend, React dashboard, encrypted credential vault,
RBAC, API-key management, local validation lab, and 60+ built-in modules across
Active Directory, Windows, Linux, cloud, network, credential, lateral movement,
EDR/OPSEC, and AI-assisted planning.

## Facebook Post - Casual Community Version

```text
Hi all, I am sharing ARES v6, a project I have been building as an authorized
red-team engagement framework.

ARES is designed to help structure an assessment from campaign setup to module
execution, findings, OPSEC review, and report generation. It has a FastAPI
backend, React dashboard, encrypted credential vault, RBAC, API key management,
local validation lab, and 60+ built-in modules across AD, Windows, Linux, cloud,
network, credential, lateral movement, EDR/OPSEC, and AI-assisted planning.

What it does:
- Create scoped campaigns so testing stays inside the approved target range.
- Run modules through a dashboard or API, with dry-run validation first.
- Track findings, CVSS summaries, graph data, reports, and telemetry.
- Manage API keys and account security from the dashboard.
- Generate HTML reports with evidence and remediation sections.
- Run a local validation lab to confirm auth, validation, reports, and cleanup.

What it is not:
- Not a C2 framework.
- Not an implant/beacon framework.
- Not for initial access or unauthorized testing.

It is intended for labs, internal security teams, and authorized engagements.
Feedback is welcome, especially around UX, docs, module quality, and defensive
validation workflows.

GitHub: YOUR_GITHUB_LINK
Docs: YOUR_DOCS_LINK
```

## Facebook Post - More Professional Version

```text
I am releasing ARES v6: an authorized red-team engagement automation framework.

ARES focuses on campaign discipline: explicit scope, RBAC, dry-run validation,
module orchestration, encrypted credential storage, OPSEC decision support, and
report generation. The goal is to make red-team workflows more structured,
auditable, and easier to review.

Core features:
- FastAPI backend and React dashboard.
- Campaign creation, cleanup, findings, reports, graph, strategy, and live views.
- 60+ built-in modules for AD, Windows, Linux, cloud, network, credential,
  lateral movement, EDR/OPSEC, exfil exposure checks, persistence review, and AI
  planning.
- Encrypted vault and token revocation.
- Team lead/operator/recon/reporter roles.
- Local validation lab for safe smoke testing.
- HTML report generation with ARES branding.

ARES is for authorized security testing only. It is not a C2 framework, not an
implant framework, and not intended for unauthorized access.

I would appreciate feedback from practitioners on the dashboard UX, module
coverage, documentation, and safe lab workflows.

GitHub: YOUR_GITHUB_LINK
```

## Discord Announcement

```text
Sharing a project I have been working on: ARES v6.

ARES is an authorized red-team engagement framework with:
- FastAPI backend + React dashboard
- Campaign scope enforcement
- Module orchestration with dry-run validation
- 60+ built-in modules across AD, Windows, Linux, cloud, network, credential,
  lateral, EDR/OPSEC, and AI planning
- Encrypted credential vault
- RBAC and API key management
- Report generation
- Local validation lab

Use case: labs, internal security teams, and authorized engagements where you
want structure, reporting, and OPSEC controls around module execution.

Not a C2, not an implant, not for unauthorized testing.

GitHub: YOUR_GITHUB_LINK
Docs: YOUR_DOCS_LINK
Feedback welcome, especially around UX and module docs.
```

## Discord Short Version

```text
I released ARES v6, an authorized red-team engagement framework with a FastAPI
backend, React dashboard, scoped campaigns, module orchestration, encrypted
vault, OPSEC controls, reports, API keys, and a local validation lab.

It is built for labs/internal teams/authorized engagements, not C2 or
unauthorized testing.

GitHub: YOUR_GITHUB_LINK
```

## GitHub Release Body

```text
ARES v6.0.0 is focused on making authorized red-team workflows easier to run,
review, and document.

Highlights:
- Dashboard at /dashboard with Overview, Campaigns, Modules, Reports, Graph,
  Templates, Strategy, Security, EDR/OPSEC, and Live views.
- Campaign-scoped execution and cleanup.
- 60+ built-in modules across AD, Windows, Linux, cloud, network, credential,
  lateral movement, OPSEC, EDR, exfil exposure, persistence review, and AI
  planning.
- Encrypted credential vault.
- RBAC, JWT refresh, token revocation, and API key lifecycle.
- Local validation lab for safe smoke testing.
- Branded HTML report generation.

Safety:
ARES is for authorized security testing only. Do not use it against systems you
do not own or have explicit written permission to assess.
```

## FAQ For Comments

### Is ARES a C2?

No. ARES is an orchestration and reporting framework. It does not ship implants
or beacons.

### Is it safe to run?

Run it only in a lab or explicitly authorized environment. Start with dry-run
mode and low-noise modules.

### Who is it for?

Internal security teams, red-team labs, training environments, and authorized
consulting engagements.

### Does it include a dashboard?

Yes. The dashboard is served at `/dashboard` and includes campaign, module,
report, graph, strategy, security, EDR/OPSEC, and live views.

### Can I contribute modules?

Yes. See `docs/module-development.md` and `docs/module_sdk.md`.

## Screenshot Suggestions

Use screenshots that do not expose secrets:

- Login page with ARES branding.
- Overview page with local demo data.
- Campaigns page with a fake lab campaign.
- Modules page showing filters and dry-run.
- Reports page with a generated local lab report.
- Security page with API key values hidden.

Before posting screenshots:

- Blur API keys.
- Blur passwords.
- Blur tokens.
- Blur real IPs/domains unless they are `localhost` or lab-only.
- Do not show `.env`.

