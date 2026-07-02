# ARES Frontend

The dashboard lives in `frontend/` and is a React + TypeScript + Vite app built
for the FastAPI backend.

## Runtime

- Development: `cd frontend && npm ci && npm run dev`
- Production: `npm run build`, then FastAPI serves `frontend/dist` at `/dashboard`
- Vite base path: `/dashboard/`
- API proxy: main FastAPI routes, not legacy dashboard shadow routes

## Auth

- Login calls `POST /auth/token` with `application/x-www-form-urlencoded`.
- Refresh calls `POST /auth/refresh` with JSON `{ "refresh_token": "..." }`.
- Access tokens are held in memory.
- Refresh tokens are stored in `sessionStorage`; React output escaping and the
  FastAPI CSP reduce script injection risk.
- Logout calls `POST /auth/logout` and clears local token state.

## Routes

- `/` overview: health, telemetry, campaign summary
- `/campaigns`: list, create, detail, delete, findings, CVSS, diff, restore, dry-run plan
- `/modules`: catalog filters, backend-derived dynamic params, dry-run default
- `/reports`: generate, list, and authenticated download for campaign reports
- `/graph`: graph, attack paths, BloodHound ingest
- `/templates`: list templates and generate plans
- `/strategy`: active engagements and role-gated engagement start
- `/security`: profile, password change, API keys, audit, users
- `/edr`: bypass telemetry and outcome reporting
- `/live`: `WS /ws/campaigns/{campaign_id}/events?token=<token>`

## Safety

Module forms are built from `GET /modules` `param_schema`; fields are not
hardcoded in the frontend. Module runs default to `dry_run=true`, and
high-noise or sensitive modules require explicit UI confirmation. Backend RBAC
remains the enforcement boundary.
## Runtime UX State

Dashboard result panels are context-aware. Modules, reports, graph ingest, templates, strategy, and EDR/OPSEC views keep their latest result only while the selected campaign/module/input still matches the action that produced it. Changing page context hides stale output instead of showing old JSON under a new selection.

Long-running actions should show a loading state on the button or result area. Operators should be able to tell that ARES is processing a request without watching the terminal.

The Live page owns a browser WebSocket connection. Navigating away closes that connection, so users reconnect when they return to the page.
