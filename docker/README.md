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
