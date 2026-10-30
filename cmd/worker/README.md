# Worker runtime

The `worker` binary owns every background loop in the platform.
The API process never ticks a background timer — if a task must
survive an API restart, it lives here.

## Jobs

| Name              | What it does                                               |
| ----------------- | ---------------------------------------------------------- |
| `session_sweep`   | Drops expired / revoked `sessions` rows.                   |
| `unlock_sweep`    | Drops expired `box_unlock_sessions` rows.                  |
| `share_expiry`    | `status='active' AND expires_at < now()` → `status='expired' + purge_requested_at`. |
| `share_purge`     | For each share with `purge_requested_at`, delete the stage blob, the `share_objects` row, and stamp `status='purged'`. |
| `outbox_dispatch` | Claim `domain_outbox` rows via SKIP LOCKED, call the injected `Deliver`, mark dispatched or back off. |

Intervals via env: `WORKER_SWEEP_INTERVAL` (5m), `WORKER_SHARE_INTERVAL`
(1m), `WORKER_OUTBOX_INTERVAL` (15s).

## HTTP surface

- `GET /healthz` — liveness (always 200).
- `GET /readyz` — readiness; pings the pg pool.
- `GET /api/v1/worker/sweep-stats` — last-run timestamp + cumulative
  counts for every job above.
- `GET /api/v1/worker/jobs` — registered job names.

## Trust posture

- Reads `DATABASE_URL` and `SERVER_MASTER_KEY` (for the share purge
  path — deleting the stage blob is enough; the key is only needed
  when opening one, which the worker does not do).
- Never touches `BOX_STORAGE_ROOT` directly.
- Binds `WORKER_ADDR` (default `:8083`); do not expose externally.
