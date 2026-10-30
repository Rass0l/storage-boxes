# Implementation Notes

This directory is operator-facing guidance: how the shipped runtime
behaves, where state lives, and how to recover. For architectural
rationale see `/docs/adr/`; for API contracts see `/api/openapi/`.

## Where to start

Restricted-share, audit, and recovery docs are the authoritative
operator story:

- `shares.md` — temporary-link + restricted-share lifecycle, the four
  share statuses, recipient / challenge / claim tables, what the
  no-open request paths do and do not record.
- `audit.md` — event type catalog, append-only guarantees, recipient
  attribution, risk signals.
- `backup-restore.md` — full backup / restore / recovery runbook.
  This is the file operators should read before running
  `scripts/backup.sh` or `scripts/restore.sh`.
- `jobs-boundaries.md` — worker job catalog with interval env vars
  and idempotency contract. Reconciliation + claim expiry behavior
  lives here.
- `hardening.md` — production config validation, readiness probes,
  backup/restore summary.

## Module boundaries

- `identity-boundaries.md` — auth, session, role binding.
- `vault-boundaries.md` — box, file-entry, crypto material.
- `shares-boundaries.md` — share token secrecy + persistence contract.
- `audit-boundaries.md` — what lives in `audit_events` vs
  `share_access_events` vs `risk_signals`.

## Mechanism notes

- `server-master-key.md` — `SERVER_MASTER_KEY` handling, validation
  rules per `APP_ENV`.
- `session-model.md` — sliding + absolute expiry.
- `unlock-session-durability.md` — what survives an API restart and
  what does not.
- `box-deletion-state-machine.md` — soft-delete → purge_requested
  → finalize (blobs first, metadata last).

## Historical / prior-stage notes

- `stage-1-*`, `stage2-preparation.md`, `stage3-preparation.md`,
  `repo-quality-gates.md` — retained as history. They reflect the
  staged rollout and may not match current runtime behavior.
- `backup-and-restore.md` — superseded by `backup-restore.md`; kept
  as a thin pointer.

If a note here disagrees with the code, trust the code and open a
patch for the note.
