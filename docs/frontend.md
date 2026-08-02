# ARES Frontend

The dashboard lives in `frontend/` and is a React + TypeScript + Vite app built
for the FastAPI backend.

## Runtime

- Development: run `ares dashboard dev --no-reload` from the repository root.
  It starts the FastAPI API on `http://127.0.0.1:8080` and the Vite dashboard
  on `http://127.0.0.1:5173/dashboard/` in one terminal.
- Windows virtualenv: `.\.venv\Scripts\ares.exe dashboard dev --no-reload`.
- Browser open can be skipped with `ares dashboard dev --no-open`.
- Backend and UI bind addresses can be changed with `--api-host`,
  `--api-port`, `--ui-host`, and `--ui-port`.
- Uvicorn reload can be disabled with `--no-reload`.
- If `frontend/node_modules` is missing, run `ares dashboard dev --install` or
  run `npm ci` from `frontend/`.
- Production/static serving: `npm run build`, then FastAPI serves
  `frontend/dist` at `/dashboard`
- Vite base path: `/dashboard/`
- API proxy: main FastAPI routes, not legacy dashboard shadow routes

Manual fallback for troubleshooting:

```powershell
Set-Location "<ARES repo root>"
.\.venv\Scripts\python.exe -m uvicorn ares.api.server:app --host 127.0.0.1 --port 8080 --reload
```

```powershell
Set-Location "<ARES repo root>\frontend"
& "C:\Program Files\nodejs\npm.cmd" run dev -- --host 127.0.0.1 --port 5173
```

Then open `http://127.0.0.1:5173/dashboard/`.

## Auth

- Login calls `POST /auth/token` with `application/x-www-form-urlencoded`.
- Refresh calls `POST /auth/refresh` with JSON `{ "refresh_token": "..." }`.
- Access tokens are held in memory.
- Refresh tokens are stored in `sessionStorage`; React output escaping and the
  FastAPI CSP reduce script injection risk. This residual browser-token/XSS
  exposure is intentionally deferred to the HttpOnly-cookie/CSRF conversion in
  Phase 5B.2.
- Logout calls `POST /auth/logout` and revokes only the current device family;
  **Logout all devices** calls `POST /auth/logout-all`. Both clear local state
  even when the remote request fails.
- Refresh is single-flight within a tab and uses a non-secret family-derived
  coordination key, generation counter, Web Locks, `localStorage`, and
  `BroadcastChannel` for cross-tab exclusion/invalidation. Raw access or
  refresh tokens are never posted across tabs or written to `localStorage`.
  A tab that loses a refresh race discards its session and requires login; it
  never retries a consumed predecessor.
- Each main campaign WebSocket connection first requests a 30-second,
  single-use ticket with authenticated `POST
  /campaigns/{campaign_id}/websocket-ticket`. The ticket exists only across the
  asynchronous connection barrier and is never stored in React state,
  `localStorage`, or `sessionStorage`.

## Routes

- `/` overview: health, telemetry, campaign summary
- `/campaigns`: `List`, `Scope`, and `Findings` tabs for list/create/detail/delete, findings, CVSS, diff, restore, and dry-run plan actions
- `/modules`: `Catalog`, `Run Panel`, and `Results` tabs for catalog filters, backend-derived dynamic params, dry-run default, and execution output
- `/reports`: `Generate` tab for report creation; `Library` tab for listing artifacts, authenticated download, per-report delete, and Delete all/Clear library cleanup. Successful delete actions update rows and artifact counts without a full page reload.
- `/graph`: `Entities`, `Attack Paths`, and `Ingest` tabs for graph review, attack paths, and BloodHound ingest
- `/templates`: `Templates` and `Plan Builder` tabs for listing templates and generating plans
- `/strategy`: `Objective`, `Active`, and `Result` tabs for active engagements and role-gated engagement start
- `/security`: `Account`, `API Keys`, and `Audit` tabs for profile, password change, API keys, audit, and users
- `/edr`: `Knowledge Base` and `Report Outcome` tabs for bypass telemetry and outcome reporting
- `/live`: `Stream` and `Buffer` tabs backed by the ticket-only `WS
  /ws/campaigns/{campaign_id}/events?ticket=<one-time-ticket>` route. Every
  reconnect requests a fresh ticket; bearer/API-key query credentials are no
  longer supported.

## Shell Controls

- The left sidebar handles route navigation.
- The topbar menu button collapses and expands the sidebar.
- Topbar quick search is client-side navigation over currently loaded page
  names/routes, campaigns, modules, reports, and templates. It is not a
  server-backed search across unloaded historical data.
- The notification bell is the health/status surface. There is no separate
  topbar status pill for online/offline state.
- The bell badge counts unread notifications only. Opening the drawer marks
  visible notifications as read; individual dismiss and clear-all remove
  notifications from the current session.
- Notification state must not persist bodies, API keys, tokens, stack traces,
  or raw payloads.
- The topbar keeps the user identity plus current-device and all-device logout
  actions.

## Safety

Module forms are built from `GET /modules` `param_schema`; fields are not
hardcoded in the frontend. Module runs default to `dry_run=true`, and
high-noise or sensitive modules require explicit UI confirmation. Backend RBAC
remains the enforcement boundary.
## Runtime UX State

Dashboard result panels are context-aware. Modules, reports, graph ingest, templates, strategy, and EDR/OPSEC views keep their latest result only while the selected campaign/module/input still matches the action that produced it. Changing page context hides stale output instead of showing old JSON under a new selection.

Long-running actions should show a loading state on the button or result area. Operators should be able to tell that ARES is processing a request without watching the terminal.

The Live page owns a browser WebSocket connection. It checks the captured
session revision, campaign, effect, and connection generation after ticket
issuance and discards a late response after logout, account replacement,
campaign change, cleanup, or unmount. A same-session access-token refresh does
not invalidate that barrier. Navigating away closes the connection, so users
request a fresh ticket when they return.

Every token response carries a refresh generation and non-secret coordination
key. A response is installed only if it belongs to the captured session and is
the exact next generation. Logout, account replacement, replay/family
revocation, or peer-tab generation advancement increments the session revision,
clears credentials, closes bearer-backed WebSockets through normal lifecycle
handling, and prevents an infinite refresh loop. A same-family token refresh
does not change identity until another tab wins it.

Production frontend and backend versions must roll out atomically, with
existing sockets drained. Mixed old/new versions are unsupported, and rollback
replaces both together while leaving additive migrations installed. Use
HTTPS/WSS directly: one-time tickets can remain visible in browser developer
tools and upstream handshake processing. The nginx TLS access log omits query
strings through `$uri`; its plaintext port-80 `$request_uri` redirect is an
unsupported ticket boundary. The default-disabled legacy dashboard WebSocket
retains its separate limitations.
