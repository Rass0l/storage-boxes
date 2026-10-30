# Backup, Restore, and Recovery

This document is the single source of truth for what the platform backs up,
how to restore it, what consistency guarantees apply, and what readiness
expectations exist during recovery.

## What is backed up

The platform owns three persistent state sources. All three are captured by
`scripts/backup.sh`:

| Artifact              | Contents                                                               | Tool        |
|-----------------------|------------------------------------------------------------------------|-------------|
| `postgres.dump`       | All schema + rows: `shares`, `share_objects`, `share_recipients`, `share_challenges`, `share_claims`, `share_access_requests`, `share_access_events`, `audit_events`, `domain_outbox`, `risk_signals`, vault/file metadata, sessions. Access-request state, decision metadata, and the recipient-policy changes approvals cause are all captured in this whole-DB dump (no separate handling). | `pg_dump --format=custom` |
| `share_stage.tgz`     | Staged (per-share-encrypted) share payloads under `SHARE_STAGE_ROOT`.  | `tar -C root -czf … .` (content-style) |
| `box_storage.tgz`     | Vault blobs under `BOX_STORAGE_ROOT`, laid out as `{box_id}/{storage_key}`. | `tar -C root -czf … .` (content-style) |
| `manifest.env`        | Creation timestamp, migration watermark, per-artifact SHA-256.         | shell     |

**Archive layout.** Backups produced by the current `scripts/backup.sh`
tar the **contents** of `BOX_STORAGE_ROOT` / `SHARE_STAGE_ROOT` rather
than the named root directory. That makes the archive path-agnostic:
the target machine can use any `BOX_STORAGE_ROOT` / `SHARE_STAGE_ROOT`
and `scripts/restore.sh` will always land the contents exactly there.
Older archives that were taken with the legacy
`tar -C dirname basename` shape still restore correctly —
`scripts/_extract-archive.sh` detects the single-top-dir case and
strips one level on the fly.

## Ordering and consistency

Before starting the backup, stop API, share-gateway, and worker processes and
keep them stopped until all artifacts are complete. Leave PostgreSQL running.
The script does not stop services or enforce this precondition for you. Store
the server master key separately with protected recovery credentials; it is
not included in the database/blob snapshot.

1. **Postgres is dumped first.** `pg_dump --format=custom` produces a
   transactionally consistent snapshot.
2. **Blobs are tarred after the dump, with writers and purgers stopped.** A
   concurrent purge can delete bytes referenced by the earlier database dump.
   Atomic file writes alone cannot guarantee database-plus-blob consistency.
   Coordinated storage snapshots would require a separately validated design.
3. **Append-only tables are preserved.** `audit_events`,
   `share_access_events`, and `share_challenges` are dumped with their
   triggers; the `prevent_append_only_mutation()` function is part of
   the schema and is restored unchanged.

What this does **not** guarantee: a share that was mid-purge at the
moment of backup will be restored with `purge_requested_at IS NOT NULL`
but `status IN ('active','revoked','expired')`. The worker's
`SharePurgeJob` re-discovers and finishes the purge on its next tick. This
is by design — purge state is idempotent.

## Restore procedure

```bash
SRC=/backups/2026-04-17 DATABASE_URL=postgres://... \
  bash scripts/restore.sh
```

The script runs these steps in order (dry-run-able via `DRY_RUN=1`):

1. **Integrity.** Verifies every artifact's SHA-256 against
   `manifest.env`. Fails closed with exit code `4` on mismatch. Older
   archives that predate the manifest can be restored with
   `SKIP_INTEGRITY_CHECK=1` (not recommended).
2. **Watermark.** Reads `migration_watermark_num` from the manifest
   and compares it to the highest `NNN_*.up.sql` in the target code's
   `migrations/` directory. Refuses with exit code `5` if the archive
   watermark is higher — this catches the silent "older binary
   restoring newer schema" footgun. Override the migrations directory
   with `MIGRATIONS_DIR=…` when restoring from a packaged release.
3. **Empty-target guard.** Refuses to run against a non-empty DB
   unless `FORCE=1` (protects against accidental
   restore-on-top-of-live). Uses `to_regclass` so a first-ever restore
   against a schema-less target works cleanly.
4. `pg_restore --clean --if-exists --no-owner --exit-on-error` — drops
   existing schema objects and rewrites them from the dump.
   `--exit-on-error` stops the script before the blob untar if the
   dump can't replay cleanly.
5. Untars `share_stage.tgz` into `SHARE_STAGE_ROOT`.
6. Untars `box_storage.tgz` into `BOX_STORAGE_ROOT`.
7. Invokes `scripts/restore-verify.sh` which:
   - confirms core tables exist (`shares`, `share_recipients`,
     `share_challenges`, `share_claims`, `share_access_requests`,
     `audit_events`, etc.);
   - confirms append-only triggers are installed on `audit_events`,
     `share_access_events`, and `share_challenges`;
   - confirms `share_access_events.recipient_id` exists
     (migration 016);
   - confirms `schema_migrations` is populated;
   - asserts no orphan `share_claims` / `share_recipients` rows;
   - asserts recipient-FK integrity: every `share_claims.recipient_id`
     resolves, and every NON-NULL `share_challenges.recipient_id` /
     `share_access_events.recipient_id` resolves (catches a partial dump
     that kept children but dropped their recipient parents);
   - reports (informational, not a failure) active claims whose
     recipient is revoked — the worker's `ShareReconciliationJob`
     converges these on the next tick;
   - asserts access-request integrity: no orphan `share_access_requests`
     (every row's `share_id` resolves) and every NON-NULL `recipient_id`
     resolves to a `share_recipients` row (both hard failures, exit `5`);
   - reports (informational, not a failure) the soft mismatches the
     worker's `AccessRequestCleanupJob` converges: approved requests with
     no recipient link (legitimately NULLed when a share was purged),
     approved requests pointing at a now-revoked recipient (access later
     withdrawn), pending requests past TTL, and pending requests whose
     `(share, email)` already maps to an active recipient;
   - confirms the audit ledger + dispatch queue (`audit_events`,
     `domain_outbox`) are present and reports the pending undispatched
     outbox count the worker will flush after boot;
   - cross-checks `share_objects` ↔ stage blobs in **both** directions
     — every row has a file AND every file has a row. Orphan blobs
     above `VERIFY_MAX_ORPHAN_BLOBS` (default 0) fail the verifier.
   - cross-checks `file_objects` ↔ vault blobs in both directions with
     the same stringency. Each row must have
     `$BOX_STORAGE_ROOT/{box_id}/{storage_key}` on disk; each file
     two levels deep under `$BOX_STORAGE_ROOT` must have a matching
     row. Orphan vault blobs above `VERIFY_MAX_ORPHAN_VAULT_BLOBS`
     (default 0) fail the verifier — vault loss is unrecoverable, so
     this threshold is intentionally stricter than the stage side
     would need to be.
8. Optional: when `RESTORE_WAIT_FOR_WORKER=1` and `WORKER_URL=…` are
   set, polls `$WORKER_URL/api/v1/worker/sweep-stats` until the
   `reconciled` counter advances (default timeout 120s, override with
   `WORKER_WAIT_SECONDS`). This lets CI pipelines chain
   `scripts/restore.sh && start-gateway && start-api` without manual
   inspection.

## Bringing services back up

Services come back in a strict order. Deviating is what produces
inconsistencies (stale claim cookies working against purge-pending
shares, or authenticated writes landing before cleanup has run).

| Step | Service          | What happens                                                                                                                                                                                                                                 |
|-----:|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  1   | `worker`         | Boot sequence runs each job once, synchronously, before entering the main tick loop: `ShareExpiryJob` → `SharePurgeJob` → `ClaimExpiryJob` → `ShareReconciliationJob`. The reconciler revokes any claim pointing at a non-deliverable share, plus any still-active claim whose recipient has been revoked (cascade-miss safety net). |
|  2   | `share-gateway`  | Public + restricted delivery. Safe once the worker's first reconcile tick has landed (no restricted recipient will hit a stale claim the worker was about to clean up).                                                                        |
|  3   | `api` + `edge`   | Authenticated API + TLS front door. Last, so no writes land before the worker's view of state is consistent.                                                                                                                                  |

Gate each step on the previous one's `/api/v1/worker/sweep-stats`
counters (`reconciled`, `shares_purged`, `claims_expired`). `/readyz`
on every service is only a pg-reachability probe — it returns `ready`
as soon as the database is reachable and does NOT wait for the
reconcile tick. Operators who conflate readyz with "safe to accept
traffic" will bring API up too early after a restore.

## Readiness and maintenance expectations

- **Before restore starts:** Put the platform in maintenance by stopping
  the `api` and `share-gateway` processes. Leaving them running will
  cause `/readyz` flapping during `pg_restore`.
- **During `pg_restore`:** The target DB is momentarily without a
  schema. Any stray connection attempting reads will fail — this is
  expected.
- **After restore, before worker is ready:** Recipient claim cookies
  that survived the restore may briefly work against a share whose
  `purge_requested_at` has fired. The worker's first reconciliation
  tick closes this gap. For stricter operations, invalidate claims
  outright after a restore by running:
  ```sql
  UPDATE share_claims SET revoked_at = now()
   WHERE revoked_at IS NULL;
  ```
- **RPO / RTO:** The platform is designed for nightly `backup.sh` runs.
  RPO is one backup cadence; RTO is dominated by the size of
  `share_stage.tgz` (typically minutes).

## Ownership boundary

Backup/restore tooling **never mutates share state directly** other than
the `pg_restore`'s schema-level operations. All business-state
reconciliation (claim revocation, purge completion, expired share
rollover) is owned by the worker and lands in `audit_events` as
normal. Operators should rely on the audit trail to confirm that
post-restore cleanup has run, not on ad-hoc SQL.
