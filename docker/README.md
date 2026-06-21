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
