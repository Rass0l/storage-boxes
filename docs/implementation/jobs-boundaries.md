# Jobs Module Boundaries

Jobs own asynchronous work that must survive a crash of any single
process. `cmd/worker` is the sole runtime that drives them; the API
process stays request-scoped and never ticks a background loop.

## Implemented

| Job                   | Source                                           | Interval env                 |
| --------------------- | ------------------------------------------------ | ---------------------------- |
| Session sweep         | `identityinfra.PGSessionStore.Sweep`             | `WORKER_SWEEP_INTERVAL`      |
| Unlock sweep          | `vaultinfra.PGUnlockSessionStore.Sweep`          | `WORKER_SWEEP_INTERVAL`      |
| Share expiry          | `jobsapp.ShareExpiryJob` (→ `status=expired`)    | `WORKER_SHARE_INTERVAL`      |
| Share purge           | `jobsapp.SharePurgeJob` (deletes stage + row)    | `WORKER_SHARE_INTERVAL`      |
| Box purge             | `jobsapp.BoxPurgeJob` (finalizes soft-deleted)   | `WORKER_SHARE_INTERVAL`      |
| Claim expiry          | `jobsapp.ClaimExpiryJob` (revokes past-TTL)      | `WORKER_SHARE_INTERVAL`      |
| Share reconciliation  | `jobsapp.ShareReconciliationJob` (see below)     | `WORKER_RECONCILE_INTERVAL`  |
| Access request cleanup| `jobsapp.AccessRequestCleanupJob` (see below)    | `WORKER_SHARE_INTERVAL`      |
| Outbox dispatch       | `jobsapp.OutboxDispatchJob` (SKIP LOCKED claim)  | `WORKER_OUTBOX_INTERVAL`     |

All jobs are idempotent:
- Session / unlock sweeps use `DELETE … WHERE expires_at < $1`.
- Share expiry only transitions rows whose current status is `active`.
- Share purge runs delete-if-exists on both the stage blob and the
  `share_objects` row, then sets `status = purged`. A stage-blob
  delete failure leaves `purge_requested_at` set and the status
  unchanged, so the next tick retries. Status only flips to `purged`
  once the stage delete actually succeeded — no lying about on-disk
  state.
- Box purge walks `status='deleting'` rows, drives each associated
  share through SharePurgeJob.runOne, then calls vault.FinalizeBox
  only after every share has reached `purged`. FinalizeBox wipes
  on-disk blobs BEFORE hard-deleting metadata — a blob-wipe failure
  leaves `status='deleting'` so the next tick retries. Safe across
  restarts because both halves read/write persisted state.
- Outbox claim uses `FOR UPDATE SKIP LOCKED` + `RETURNING`; a failed
  `Deliver` sets `available_at = now() + backoff` instead of flipping
  `dispatched_at`.
- Claim expiry stamps `revoked_at` on any `share_claims` row whose
  `expires_at` has passed and `revoked_at` is still NULL. Each
  revocation emits `shares.claim_expired` with
  `reason=ttl` and the recipient / share IDs in metadata. A claim
  that is already revoked is skipped — the job is safe to re-run.
- Share reconciliation runs on boot (once, synchronously, before the
  main tick loop starts) and then every `WORKER_RECONCILE_INTERVAL`.
  It converges two classes of stale claim:
  1. claims pointing at non-deliverable shares (`ListPurgeCandidates`),
     emitting `shares.claim_revoked` with
     `reason=reconciled_against_share_state`; and
  2. still-active claims whose recipient row has been revoked
     (`ListActiveWithRevokedRecipient` — the cascade-miss safety net),
     emitting `shares.claim_revoked` with
     `reason=recipient_revoked_reconciled`.
  Delivery already refuses both cases at request time
  (`OpenWithClaim` re-checks share deliverability and the recipient
  row); reconciliation converges the stored claim state and audit
  trail. A single summary `shares.reconciled` event with
  `claims_revoked` / `shares_scanned` counts is emitted per run. This
  is what closes the post-restore "orphan claims" gap — operators
  should look at the `reconciled` counter on `sweep-stats` to confirm
  the first tick has run before bringing API + gateway up.
- Access request cleanup runs on the share tick (and once on boot via
  the same `runShare` call) and converges stale `share_access_requests`
  rows to a terminal status: pending rows past `expires_at` →
  `expired` (`reason=expired_ttl`); pending rows on a non-deliverable
  share → `expired` (`reason=share_unavailable`); pending rows whose
  `(share, email)` already maps to a non-revoked recipient →
  `superseded` (`reason=recipient_active`); and **approved rows whose
  recipient state is missing** (`recipient_id IS NULL`) →
  `superseded` (`reason=recipient_missing`) via
  `SupersedeOrphanedApprovals` (an atomic `UPDATE … RETURNING`). That
  last pass is the spec's "approved request whose recipient state is
  missing or inconsistent" reconciliation; atomic approval
  (`ApproveAtomic`) prevents the state from a partial write, so it only
  catches restore / migration / out-of-band-deletion leftovers. Each
  transition emits `shares.access_request_expired` / `_superseded`; a
  summary `shares.access_requests_reconciled` carries the
  `expired`/`superseded`/`orphaned_approvals` counts. Every transition is
  status-guarded (`WHERE status='pending'` for Decide, `WHERE
  status='approved' AND recipient_id IS NULL` for the orphan pass), so the
  job is idempotent across runs and resolves any owner-approve /
  worker-supersede race to a single terminal transition. Unlike share
  reconciliation it is NOT boot-gated before readiness — a pending or
  half-applied access request grants nothing, so converging it is not
  delivery-critical. Surfaced on `sweep-stats` as
  `access_requests_cleaned`.

## Still planned

- Dead-letter table + operator query for outbox rows past N attempts.
- SIEM / Slack `Deliver` implementations plugged into the outbox.
- Orphan blob GC for `SHARE_STAGE_ROOT` (covers stage files whose
  share row was cascade-deleted before purge).
- Crypto key rotation migration job.

## Runtime contract

- Worker exposes `/healthz`, `/readyz`, `/api/v1/worker/sweep-stats`
  (last-run + counts), and `/api/v1/worker/jobs` (registered list).
- Intervals clamp to `time.ParseDuration` values; unparseable values
  fall back to the defaults noted above.
- Jobs must never call back into the API process; they talk to
  Postgres + disk directly, the same way `cmd/api` does.
