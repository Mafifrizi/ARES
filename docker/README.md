# ARES Docker

## Files

| File | Purpose |
|------|---------|
| `Dockerfile.prod` | **Production** — Node frontend build, Python runtime, non-root user, healthcheck |
| `Dockerfile.dev`  | **Development** — single-stage, editable install (`pip install -e ".[dev]"`), source mount |
| `docker-compose.prod.yml` | Production compose (use with `Dockerfile.prod`) |
| `docker-compose.dev.yml`  | Development compose (use with `Dockerfile.dev`, mounts source for hot-reload) |

## Usage

### Production
```bash
docker compose -f docker/docker-compose.prod.yml up -d
```

The production image runs `npm ci && npm run build` in a Node stage, copies
`frontend/dist` into `/app/frontend/dist`, and FastAPI serves it at
`/dashboard`. `/health` is served by the API and does not depend on the
dashboard files.

### Development
```bash
docker compose -f docker/docker-compose.dev.yml up
```

Development compose starts:

- `ares-api` at `http://localhost:8080`
- `ares-frontend` at `http://localhost:5173/dashboard`

The Vite server proxies API and WebSocket traffic to `ares-api`.
Development browser cookies use the distinct `ares-dev-*` names only while
`ARES_DEBUG=true`, the configured origin is exactly `http://localhost:5173`,
and the request host is loopback. Production requires one exact HTTPS
`ARES_BROWSER_ORIGIN`; browser auth is same-origin and does not use CORS.

## Environment
Copy `.env.example` to `.env` and fill in secrets before starting either stack.
## Existing database adoption

Containers do not adopt unversioned databases during startup. Before replacing
an existing deployment, stop every application worker, take the required backup,
and run the explicit verification/adoption workflow described in
[`docs/database-migrations.md`](../docs/database-migrations.md). PostgreSQL
adoption is serialized with a transaction-scoped advisory lock; SQLite adoption
requires exclusive ownership and a new durable backup target. Keep additive
migrations installed if the application image is rolled back.

Revision `0009` introduces authoritative refresh-token families and forces a
one-time browser reauthentication. Drain WebSockets and stop every old
container before the database upgrade, then start the matching backend and
frontend together. Mixed workers are unsupported because managed ownership is
revision-exact. A container-image rollback does not downgrade the additive
schema; return to a compatible forward image instead.

Revision `0010` adds execution-lifecycle persistence without activating a live
gateway. Drain all processes externally, back up, migrate, and then start only
the matching 0010-aware API compatibility image. No supported operator budget
command exists in this phase, so do not configure execution capacity with
direct SQL. Legacy execution is not automatically disabled by the migration.

## Browser-session rollout

Refresh sessions use host-only HttpOnly cookies and CSRF/Origin validation.
Access tokens remain in browser memory, and API keys remain the automation
credential. Deploy backend and frontend atomically, drain existing sockets,
and require existing users to sign in again; the old browser refresh value is
deleted from `sessionStorage` and is not bridged into the cookie transport.
Mixed versions are unsupported. That browser-session change remains revision
`0009`; the current Alembic head is the separate additive revision `0010`.
Rollback replaces compatible application images without a database downgrade.
The nginx TLS log and HTTP redirect use `$uri`, and the
redirect drops query strings instead of reflecting them.
