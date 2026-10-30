# Operational hardening

## Edge boot verification

The redirect target for `HTTP → HTTPS` is rendered at container start
from `nginx.conf` (carrying the placeholder `:__EDGE_HTTPS_PORT__`)
via a small `sed` step in the compose entrypoint. Two fast,
docker-less guards in `test/integration/edge_config_test.go` keep the
template, the entrypoint, and the redirect format in sync with the
live compose behavior asserted by
`test/e2e/compose_edge_test.go` (gated by `compose_e2e`).

## Edge hardening baseline

`deployments/compose/edge/nginx.conf` carries the hardening floor
for the TLS terminator:

- **TLS 1.3 only** (`ssl_protocols TLSv1.3`). 1.2 is kept off so a
  cipher downgrade can't happen; switch to `TLSv1.2 TLSv1.3` only
  when an older client base must be supported.
- **`ssl_session_tickets off`** + shared session cache — forward
  secrecy stays intact without the ticket-key rotation concern.
- **`server_tokens off`** so `Server:` is bare `nginx` instead of
  `nginx/1.27.5`. Verified live by `compose_edge_test.go`.
- **Rate limit on `/s/`** via a 30 r/s per-client-IP zone with a
  20-burst, returning 429 above that. Dampens brute-force token
  probing; live compose test fires 80 rapid requests and asserts at
  least one 429.
- **`proxy_buffering off` + 300s timeout on `/s/`** so large shared
  files stream through the edge without materializing on disk.
- **Content-Security-Policy + Permissions-Policy** on HTTPS
  responses, layered on top of HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, and `Referrer-Policy`.
- **HTTPS `/healthz`** — the HTTP-only liveness probe on `:8088`
  is mirrored on `:8443` so upstream checks don't need to follow
  a redirect.

`test/integration/edge_config_test.go:TestEdgeNginxHardeningDirectives`
parses `nginx.conf` and asserts every directive above, and
forbids legacy signals (`TLSv1.0`, `HIGH:!aNULL:!MD5`). A config
regression is caught at unit-test speed before the slow compose
smoke run.

## Edge TLS

`deployments/compose/docker-compose.yml` adds an `edge` nginx service
that fronts the SPA, `/api/*` (to api), and `/s/*` (to share-gateway)
over HTTPS. Generate a local dev cert with
`scripts/gen-dev-tls.sh`; in production bind-mount real certs at
`deployments/compose/edge/tls/{fullchain,privkey}.pem`. HSTS,
`X-Content-Type-Options`, `X-Frame-Options`, and Referrer-Policy are
set at the edge.

## Trusted proxies

`TRUSTED_PROXIES` (comma-separated CIDRs or IPs) tells the enrichment
middleware which direct peers are permitted to set
`X-Forwarded-For`. When the request's direct peer is trusted, the
left-most XFF entry becomes the recorded `remote_ip`; otherwise the
direct peer IP is used.

## Config validation

`platform/config.Load` fails fast when `APP_ENV ∈ {production,
staging}` and `SERVER_MASTER_KEY` is not a 64-hex (32-byte) string.
`RequireTLS` is set to true for production-like environments so the
api's identity middleware sets the `Secure` flag on session cookies.

## Backup & restore

`scripts/backup.sh` dumps Postgres (custom format) and tars
`BOX_STORAGE_ROOT` and `SHARE_STAGE_ROOT`, and writes a `manifest.env`
with per-artifact SHA-256 and the migration watermark. Retain older
snapshots via `RETAIN_DAYS=N`.

Restore is **not symmetric** with backup — ordering matters.
`scripts/restore.sh` runs the dump, untars the stage + vault
directories, then invokes `scripts/restore-verify.sh` to check tables
exist, append-only triggers are installed, and share-object blobs are
on disk. After the script exits, the operator boots the **worker
first** — `ShareReconciliationJob` runs once on boot and revokes any
claim pointing at a no-longer-deliverable share, emitting
`shares.reconciled` with counts. API and share-gateway come up only
after `/api/v1/worker/sweep-stats` reflects a completed reconcile
tick. See `docs/implementation/backup-restore.md` for the full
runbook including RPO/RTO guidance.

## Readiness

`/readyz` on api, worker, and share-gateway all ping the pg pool and
return 503 when unreachable. Compose uses this via `healthcheck`
stanzas; a reverse proxy should gate traffic on `/readyz`. The worker
also exposes `/api/v1/worker/sweep-stats` for last-run + counts and
`/api/v1/worker/jobs` for the registered job list.
