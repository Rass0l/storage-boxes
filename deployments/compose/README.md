# Docker Compose — local & e2e stack

Storage Boxes **0.5.0**. For Windows, follow [WINDOWS.md](../../WINDOWS.md),
including local CA setup before the first start. For shared deployment,
provision a trusted certificate for the actual hostname as described in
[DEPLOYMENT.md](../../DEPLOYMENT.md). The self-signed fallback below is for
isolated testing and does not establish browser trust.

The compose stack launches everything the platform needs for local
development and for the end-to-end test suite:

| Service         | Port       | Purpose                                              |
| --------------- | ---------- | ---------------------------------------------------- |
| `postgres`      | 5432       | Postgres 16, schema owned by `migrate`               |
| `migrate`       | —          | One-shot SQL migration runner (001…017)              |
| `api`           | 8082       | Authenticated Go API (`/api/v1/*`, `/healthz`, …)    |
| `worker`        | 8083       | Session/unlock sweep, share expiry + purge, outbox   |
| `share-gateway` | 8084       | Public share downloads (`/s/{token}`), unauth        |
| `frontend`      | 5173       | Built React SPA served via nginx                     |
| `edge`          | 8088, 8443 | Nginx TLS terminator; fronts SPA + api + gateway. First boot auto-generates a self-signed cert if one isn't already mounted. Override the host ports via `EDGE_HTTP_PORT` / `EDGE_HTTPS_PORT`. |

The base stack (`make compose-up`) exposes the HTTPS edge. The dev override
(`make compose-up-dev`) additionally exposes the direct debugging ports:

- `http://localhost:5173/` — the SPA directly. Useful for dev; there
  is no TLS and no HTTP→HTTPS redirect on this port. Do not expose it
  publicly.
- `https://localhost:8443/` — through the edge. HSTS is on, the
  matching HTTP port (`:8088`) returns `301` to HTTPS, `/api/*` is
  proxied to api, and `/s/*` is proxied to share-gateway.

The base services read the untracked local `../../.env`; create it from the
example and configure unique credentials. The Windows override uses the
separately generated, untracked `.env.windows` instead.

The `api` and `worker` mount `share_stage_data` at `/data/shares` so a
share staged by the API is visible to the share-gateway and purgeable
by the worker. Trust boundaries: `share-gateway` has no vault access
and no identity; it only reads `share_objects` + the staged bytes.

## Usage

```bash
# from repo root
make compose-up        # production shape: only the edge publishes host ports
make compose-up-dev    # layer docker-compose.dev.yml: adds :5432/:8082/:8083/:8084/:5173
make compose-logs      # tail logs
make compose-down      # stop and delete volumes

# full end-to-end test against the live stack (uses the dev overlay
# so the pg-direct tests can reach :5432)
make compose-e2e

# local TLS for the edge service (self-signed; dev only)
bash scripts/gen-dev-tls.sh
```

In the production shape, reach Postgres via `docker compose exec
postgres psql …` and the worker's stats endpoint via `docker compose
exec worker wget -qO- http://localhost:8083/api/v1/worker/sweep-stats`.
`test/integration/compose_shape_test.go` locks the edge-only invariant
into CI: adding a `ports:` stanza to any non-edge service in the
base file fails the unit suite.

Browse to the configured HTTPS hostname/port using a trusted certificate.
On Windows the default is `https://localhost:18443/login`. A direct
`http://localhost:5173/login` route exists only under the debugging override.
Do not disable certificate validation or remove HSTS to repair TLS problems.

`make compose-e2e` is gated behind the Go build tag `compose_e2e` and
`COMPOSE_E2E=1` so `go test ./...` stays fast and docker-less.

## What the e2e test covers

`test/e2e/compose_stack_test.go` brings up the stack, then drives:

1. Anonymous `/auth/me` → 401; seeded login → session + CSRF cookies
2. Admin-only `/users` → 200
3. Box create (CSRF) → unlock → encrypted file upload → listing → decrypted download → folder create / move → delete → lock → logout
4. Share lifecycle: create link through `/api/v1/shares`, download via the gateway at `/s/{token}`, revoke, confirm 404 on a subsequent fetch, audit query returns the full trail.
5. Worker stats: `/api/v1/worker/sweep-stats` and `/api/v1/worker/jobs` populate; a second run of the share-expiry job is idempotent.
6. Frontend shell at `http://localhost:5173/` responds.

`t.Cleanup` always runs `docker compose down -v --remove-orphans`, so
the test leaves no volumes, containers, or networks behind.
