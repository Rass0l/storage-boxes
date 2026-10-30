# Deployment

Storage Boxes **0.5.0**. The verified default setup is the local Windows stack
in [WINDOWS.md](WINDOWS.md). Shared deployment and recovery still require the
validation described in [project status](docs/project-status.md).

## Runtime topology

| Service         | Port      | Role                                                       |
| --------------- | --------- | ---------------------------------------------------------- |
| `postgres`      | 5432      | Postgres 16; schema owned by the `migrate` job             |
| `migrate`       | —         | Idempotent SQL migration runner (001…017)                  |
| `api`           | 8082      | Authenticated Go HTTP API (`/api/v1/*`, `/healthz`)        |
| `worker`        | 8083      | Background jobs: session sweep, unlock sweep, share expiry,|
|                 |           | share purge, box purge, claim expiry, share reconciliation,|
|                 |           | access-request cleanup, domain-outbox dispatch            |
| `share-gateway` | 8084      | Public + restricted share delivery (`GET /s/{token}`,      |
|                 |           | `POST /s/{token}/verify`, `POST /s/{token}/otp`,           |
|                 |           | `POST /s/{token}/revoke-claim`,                            |
|                 |           | `POST /s/{token}/request-access`,                          |
|                 |           | `GET /s/{token}/request-status`)                           |
| `frontend`      | 80        | Built SPA served via nginx (dev host mapping: 5173)          |
| `edge`          | 8088 / 8443 (configurable via `EDGE_HTTP_PORT` / `EDGE_HTTPS_PORT`) | Nginx TLS terminator fronting api + share-gateway + SPA |

**Production-shape vs dev.** The base `docker-compose.yml` publishes
only the `edge` host ports (80/443 → 8088/8443). postgres, api,
worker, share-gateway, and frontend are reachable only on the docker
network — the same shape as a real deployment. `docker-compose.dev.yml`
is a layered override that re-publishes the internal ports for
local debugging and the pg-direct test suite:

```bash
make compose-up       # production shape (edge-only)
make compose-up-dev   # + internal ports on localhost
make compose-e2e      # test suite; uses the dev overlay automatically
```

`test/integration/compose_shape_test.go` fails the build if the base
file grows a `ports:` stanza outside `edge`.

## Bring the stack up

For Windows localhost, complete [trusted local HTTPS](WINDOWS.md#trusted-local-https)
before running the Windows launcher. For a shared deployment, obtain a
certificate for the actual public hostname from a CA trusted by every client.
Place the leaf and intermediate certificates in `deployments/compose/edge/tls/fullchain.pem`
and the matching private key in `privkey.pem` before starting. Do not copy TLS
keys or a local development CA from an existing deployment or an old archive.

```bash
cp .env.example .env
# Edit SERVER_MASTER_KEY (generate 64 hex chars with openssl rand -hex 32),
# SEED_ADMIN_PASSWORD, APP_ENV, and TRUSTED_PROXIES before shipping anywhere shared.

# Provision fullchain.pem + privkey.pem for your hostname first.
# Inspect the public certificate (this does not print its private key):
openssl x509 -in deployments/compose/edge/tls/fullchain.pem -noout -subject -issuer -dates -ext subjectAltName

make compose-up
```

The supplied Compose database uses the local evaluation credentials
`postgres:postgres`. Before a shared deployment, configure a unique database
password in the PostgreSQL service and the matching `DATABASE_URL`. For an
existing database volume, changing `POSTGRES_PASSWORD` alone does not rotate
the stored database password; update the database role as well. Keep these
deployment-specific values in untracked configuration. Set `APP_ENV=production`
and configure SMTP if using email OTP; the example defaults to development mode.

Set `SHARE_PUBLIC_BASE_URL` to the public HTTPS origin, then visit that
hostname on the configured edge port (8443 by default). Validate it with a
normal browser or `curl --fail https://your-hostname:8443/login`; do not use
`-k` or suppress certificate validation as a deployment check.

The base edge's self-signed fallback exists for isolated tests; it does not
establish browser trust and is unsuitable for shared deployment. HSTS can
prevent certificate exceptions, so provision a trusted chain before exposing
the service. Renew before expiry, validate the hostname/key/chain, and reload
Nginx after replacing files. The base stack publishes only the edge; direct
SPA/API ports are available only with the debugging override.

## Configuration

| Variable                 | Meaning                                                  |
| ------------------------ | -------------------------------------------------------- |
| `APP_ENV`                | `dev` / `test` / `staging` / `production`                |
| `DATABASE_URL`           | Postgres DSN (required)                                  |
| `SERVER_MASTER_KEY`      | 64 hex chars; **enforced** when `APP_ENV` is prod/staging|
| `BOX_STORAGE_ROOT`       | Directory for encrypted vault blobs                      |
| `SHARE_STAGE_ROOT`       | Directory for staged share bytes (separate from vault)   |
| `SHARE_PUBLIC_BASE_URL`  | External URL used in share-create responses (e.g.        |
|                          | `https://shares.example.com`)                            |
| `TRUSTED_PROXIES`        | Comma-separated CIDRs trusted for `X-Forwarded-For`      |
| `SHARE_OTP_SMTP_ADDR`    | SMTP `host:port` for restricted-share OTP email delivery |
| `SHARE_OTP_SMTP_FROM`    | Envelope/header sender for OTP emails                    |
| `SHARE_OTP_SMTP_USERNAME`| Optional SMTP PLAIN-auth username (over STARTTLS)        |
| `SHARE_OTP_SMTP_PASSWORD`| Optional SMTP PLAIN-auth password                        |
| `WORKER_SWEEP_INTERVAL`  | Session/unlock sweep period (default `5m`)               |
| `WORKER_SHARE_INTERVAL`  | Share expiry + purge period (default `1m`)               |
| `WORKER_OUTBOX_INTERVAL` | Outbox dispatch period (default `15s`)                   |
| `WORKER_RECONCILE_INTERVAL` | Share/claim reconciliation period (default `15m`)     |
| `SHARE_ACCESS_REQUEST_TTL`  | Pending access-request TTL before worker expiry (default `168h`) |
| `SEED_ADMIN_EMAIL`, etc. | Bootstrap admin credentials                              |

### Restricted-share delivery (cookies + OTP)

`APP_ENV` drives two production-safety behaviors in the share-gateway,
so set it correctly (`production` / `staging` behind TLS):

- **Claim cookie `Secure`.** The `sb_share_claim` cookie is always
  `HttpOnly; SameSite=Strict; Path=/s/<token>`. The `Secure` attribute is
  added only when `APP_ENV` is production-like (`config.RequireTLS`). On
  a local HTTP dev gateway it is omitted so the browser actually stores
  the cookie — otherwise verification can't complete over
  `http://localhost`.
- **OTP delivery.** `require_otp` shares need a one-time code delivered
  out-of-band (a different channel from the passcode). The platform ships
  an email dispatcher (`infra.SMTPOTPDispatcher`): set
  `SHARE_OTP_SMTP_ADDR` (host:port) and `SHARE_OTP_SMTP_FROM` (and
  optionally `SHARE_OTP_SMTP_USERNAME` / `SHARE_OTP_SMTP_PASSWORD` for
  PLAIN auth over STARTTLS) and the code is emailed to the recipient.
  Both the api and the share-gateway read the same vars, so the
  create-time guard and verify-time delivery agree. Without SMTP
  configured in a production-like env, creating a `require_otp` share is
  rejected (`otp_delivery_not_configured`), and the code is **never**
  returned in the verify response or written to logs. In `dev`/`test`
  the gateway sets `DevModeOTPEcho`, surfacing the code in the verify
  response purely for local testing.

## Seeded bootstrap admin

On startup, the API upserts the admin user and binds the `admin` role.
The password used is `SEED_ADMIN_PASSWORD` — the API rehashes it on
every boot, so the migration-010 placeholder hash is never authoritative.

## Persistence model

- Identity (users / credentials / sessions / roles) in Postgres.
  Sessions carry sliding `expires_at` + absolute `absolute_expires_at`.
- Vault metadata (boxes, crypto material, unlock sessions, file entries)
  in Postgres. Box creation runs in one transaction.
- Encrypted vault blobs on disk under `BOX_STORAGE_ROOT`.
- Shares metadata in Postgres (`shares`, `share_objects`,
  `share_access_events`). Staged share bytes on disk under
  `SHARE_STAGE_ROOT`, encrypted under a per-share key that is itself
  wrapped by `SERVER_MASTER_KEY`. Deleting a staged blob makes the
  share payload permanently unreadable — vault data is untouched.
- Restricted-share state in Postgres (`share_recipients`,
  `share_challenges`, `share_claims`). `share_challenges` is
  append-only (trigger-enforced, same pattern as `share_access_events`
  and `audit_events`). `share_claims` is mutable only for
  revocation / OTP-completion. `share_access_events.recipient_id`
  (migration 016) carries durable recipient attribution for every
  restricted-delivery row so audit queries don't need to reverse-join
  `share_claims`. See `docs/implementation/shares.md` for the full
  lifecycle.
- Audit in Postgres (`audit_events`, `domain_outbox`, `risk_signals`);
  append-only is enforced by trigger.

## Health probes

- `GET /healthz` — liveness (always 200 while the process is up).
- `GET /readyz`  — readiness (pings the pg pool).
- `GET /api/v1/worker/sweep-stats` (worker) — last-run timestamps
  and cumulative counts per job.
- `GET /api/v1/worker/jobs` (worker) — list of registered jobs.

## Backup & restore

Run `bash scripts/backup.sh` to snapshot the three state sources the
platform owns:

1. Postgres (metadata + audit + shares + recipients + claims) via
   `pg_dump --format=custom`.
2. `SHARE_STAGE_ROOT` (staged share payloads) via `tar`.
3. `BOX_STORAGE_ROOT` (vault blobs) via `tar`.

The backup script also writes `manifest.env` with creation timestamp,
migration watermark, and SHA-256 hashes so `scripts/restore-verify.sh`
can detect a truncated archive. Archives are path-agnostic: backup
tars the contents of each root (`tar -C $root -czf … .`), and
`scripts/restore.sh` always unpacks into the target's
`BOX_STORAGE_ROOT` / `SHARE_STAGE_ROOT` — source and target basenames
don't have to match. Legacy archives taken with the old
`dirname/basename` layout are detected and flattened automatically.

Choose a backup cadence for your recovery needs. Stop API, gateway, and worker
processes before the dump and keep them stopped until both blob archives are
complete, while leaving PostgreSQL running. Atomic blob writes do not provide
a consistent database-plus-files snapshot during concurrent writes or purges.
Rehearse restoration into isolated volumes before relying on this procedure.
`RETAIN_DAYS=N` prunes older backups.

**Restore** is not symmetric with backup — the ordering matters.
Run `SRC=/path/to/backup bash scripts/restore.sh`, which:

1. Refuses to run against a non-empty DB unless `FORCE=1`.
2. `pg_restore --clean --if-exists --no-owner` onto `DATABASE_URL`.
3. Untars the share stage into `SHARE_STAGE_ROOT`.
4. Untars the vault blobs into `BOX_STORAGE_ROOT`.
5. Invokes `scripts/restore-verify.sh` — checks core tables exist,
   append-only triggers are installed (`audit_events`,
   `share_access_events`, `share_challenges`), and share-object blobs
   are on disk.

After `restore.sh` completes, bring services up in this order —
deviating is what produces inconsistencies:

| Step | Service          | Reason                                                                                      |
|-----:|------------------|---------------------------------------------------------------------------------------------|
|   1  | `worker`         | `ShareReconciliationJob` runs once on boot and revokes claims pointing at non-deliverable shares; `SharePurgeJob` converges mid-purge state. Both emit audit records, so the `reconciled` and `shares_purged` counters on `/api/v1/worker/sweep-stats` can confirm convergence. |
|   2  | `share-gateway`  | Safe once the worker's first reconcile + purge tick has landed (no restricted recipient will hit a stale claim the worker was about to clean up). |
|   3  | `api` + `edge`   | Accepting authenticated traffic last keeps writes out of the system until the worker's view of state is consistent.                                                        |

`/readyz` on every service is a pg-reachability check only — it
doesn't wait on the reconcile tick. Operators gate Step 2/3 on the
`reconciled` counter, not on readyz alone.

See `docs/implementation/backup-restore.md` for full recovery
procedure including RPO/RTO notes and post-restore claim-invalidation
SQL.

## Tear down

```bash
make compose-down
```

Volumes are removed with `-v` so state does not leak between test
runs. Mount a named volume to persist in a long-running environment.
