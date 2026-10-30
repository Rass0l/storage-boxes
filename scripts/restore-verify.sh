#!/usr/bin/env bash
# restore-verify.sh — post-restore sanity checks. Runs after restore.sh
# has finished unpacking. Exits non-zero on any finding so the caller
# (restore.sh or a CI pipeline) surfaces the failure.
#
# Checks (each labeled in the output):
#
#  core-tables
#    The full set of tables the shipped binaries read must exist,
#    including the restricted-share tables (migration 015) and the
#    access-row recipient attribution column (migration 016).
#
#  append-only-triggers
#    audit_events, share_access_events, and share_challenges must all
#    have their prevent_append_only_mutation() trigger installed.
#    A backup taken before a given trigger migration would succeed
#    pg_restore but silently lose the append-only guarantee; this
#    check catches that case.
#
#  share_access_events.recipient_id present
#    Lets us assert migration 016 was applied. Operators chasing a
#    restore from a pre-016 archive get a clear failure instead of
#    mysterious "no recipient attribution" UI bugs.
#
#  orphan-claims / orphan-recipients
#    share_claims and share_recipients must not reference a share_id
#    that isn't present. FK CASCADE should have handled this during
#    dump; we double-check.
#
#  recipient-fk integrity
#    Every share_claims.recipient_id must resolve to a share_recipients
#    row (NOT NULL FK). Every NON-NULL share_challenges.recipient_id and
#    share_access_events.recipient_id must also resolve (those FKs are
#    ON DELETE SET NULL, so NULL is allowed but a dangling id is not).
#    Catches a partial dump that captured children but not their
#    recipient parents.
#
#  claim-recipient consistency
#    Informational: counts active (un-revoked, un-expired) claims whose
#    recipient row is revoked. The worker's ShareReconciliationJob
#    converges these after boot; we surface the count so the operator
#    knows reconciliation has pending work (not a failure).
#
#  audit-outbox
#    audit_events and domain_outbox must exist; we report the count of
#    undispatched outbox rows so the operator knows the worker has
#    pending audit fan-out to flush after boot (informational, not a
#    failure — restore.sh can optionally wait for the worker tick).
#
#  schema_migrations populated
#    A dump from the idempotent migrator always carries the
#    schema_migrations table. If it's empty the target code will try
#    to run every migration from scratch on boot, which in turn can
#    conflict with already-loaded data.
#
#  blob ↔ share_objects consistency (both directions)
#    Forward: every share_objects.storage_key has a file on disk.
#    Backward: every file on disk under SHARE_STAGE_ROOT has a
#    matching share_objects row. The backward direction catches
#    orphan blobs left after a dump taken mid-purge — the worker's
#    SharePurgeJob picks these up eventually, but the operator wants
#    to know NOW if the archive has uncollected garbage.
#
#  vault ↔ file_objects consistency (both directions)
#    Same forward/backward pattern applied to vault blobs stored at
#    BOX_STORAGE_ROOT/{box_id}/{storage_key}. Vault tars are
#    authoritative — stage blobs are re-stageable from the vault, but
#    vault loss is unrecoverable — so we flag any drift at the same
#    threshold as stage, tunable via VERIFY_MAX_ORPHAN_VAULT_BLOBS.
#
# Exit codes:
#   0  — all checks passed
#   4  — schema / trigger / migration problem
#   5  — data/blob drift detected
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL required}"
stage_root="${SHARE_STAGE_ROOT:-./.share-stage}"
box_root="${BOX_STORAGE_ROOT:-./.box-storage}"
max_orphan="${VERIFY_MAX_ORPHAN_BLOBS:-0}"
max_orphan_vault="${VERIFY_MAX_ORPHAN_VAULT_BLOBS:-0}"

fail=0

psql_t() { psql "$DATABASE_URL" -tAc "$1"; }

fail_at() {
  echo "$1" >&2
  fail="$2"
}

# -----------------------------------------------------------------------
# core-tables
# -----------------------------------------------------------------------
echo "-- core-tables"
for t in \
  shares share_objects share_access_events \
  share_recipients share_challenges share_claims \
  share_access_requests \
  audit_events domain_outbox risk_signals \
  users user_credentials role_bindings \
  boxes file_entries box_crypto_material unlock_sessions \
  schema_migrations; do
  n=$(psql_t "SELECT to_regclass('public.$t') IS NOT NULL")
  if [ "$n" != "t" ]; then
    fail_at "MISSING table: $t" 4
  fi
done

# -----------------------------------------------------------------------
# append-only-triggers
# -----------------------------------------------------------------------
echo "-- append-only-triggers"
for spec in \
  "audit_events:audit_events_no_update" \
  "share_access_events:share_access_events_no_update" \
  "share_challenges:share_challenges_no_update"; do
  table="${spec%%:*}"; trig="${spec##*:}"
  n=$(psql_t "SELECT COUNT(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname = '$trig'")
  if [ "$n" -lt 1 ]; then
    fail_at "MISSING trigger $trig on $table" 4
  fi
done

# -----------------------------------------------------------------------
# share_access_events.recipient_id (migration 016)
# -----------------------------------------------------------------------
echo "-- share_access_events.recipient_id"
n=$(psql_t "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema='public' AND table_name='share_access_events'
               AND column_name='recipient_id'")
if [ "$n" != "1" ]; then
  fail_at "share_access_events.recipient_id missing — archive pre-dates migration 016" 4
fi

# -----------------------------------------------------------------------
# schema_migrations populated
# -----------------------------------------------------------------------
echo "-- schema_migrations"
mig_count=$(psql_t "SELECT COUNT(*) FROM schema_migrations" 2>/dev/null || echo 0)
if [ "${mig_count:-0}" -lt 1 ]; then
  fail_at "schema_migrations is empty — target code would re-run migrations on boot" 4
fi
latest=$(psql_t "SELECT COALESCE(MAX(version), '') FROM schema_migrations" 2>/dev/null || echo "")
echo "   applied migration watermark: ${latest:-<unknown>}"

# -----------------------------------------------------------------------
# orphan-claims — FK guard double-check
# -----------------------------------------------------------------------
echo "-- orphan-claims"
orphan_claims=$(psql_t "SELECT COUNT(*) FROM share_claims c LEFT JOIN shares s ON s.id = c.share_id WHERE s.id IS NULL")
if [ "${orphan_claims:-0}" != "0" ]; then
  fail_at "FOUND $orphan_claims orphan share_claims" 5
fi
orphan_recipients=$(psql_t "SELECT COUNT(*) FROM share_recipients r LEFT JOIN shares s ON s.id = r.share_id WHERE s.id IS NULL")
if [ "${orphan_recipients:-0}" != "0" ]; then
  fail_at "FOUND $orphan_recipients orphan share_recipients" 5
fi

# -----------------------------------------------------------------------
# recipient-fk integrity — children must resolve to a recipient parent.
# share_claims.recipient_id is NOT NULL; share_challenges.recipient_id
# and share_access_events.recipient_id are nullable (ON DELETE SET NULL),
# so only NON-NULL values are checked.
# -----------------------------------------------------------------------
echo "-- recipient-fk integrity"
claim_bad_rcpt=$(psql_t "SELECT COUNT(*) FROM share_claims c LEFT JOIN share_recipients r ON r.id = c.recipient_id WHERE r.id IS NULL")
if [ "${claim_bad_rcpt:-0}" != "0" ]; then
  fail_at "FOUND $claim_bad_rcpt share_claims with a dangling recipient_id" 5
fi
chal_bad_rcpt=$(psql_t "SELECT COUNT(*) FROM share_challenges c LEFT JOIN share_recipients r ON r.id = c.recipient_id WHERE c.recipient_id IS NOT NULL AND r.id IS NULL")
if [ "${chal_bad_rcpt:-0}" != "0" ]; then
  fail_at "FOUND $chal_bad_rcpt share_challenges with a dangling recipient_id" 5
fi
acc_bad_rcpt=$(psql_t "SELECT COUNT(*) FROM share_access_events a LEFT JOIN share_recipients r ON r.id = a.recipient_id WHERE a.recipient_id IS NOT NULL AND r.id IS NULL")
if [ "${acc_bad_rcpt:-0}" != "0" ]; then
  fail_at "FOUND $acc_bad_rcpt share_access_events with a dangling recipient_id" 5
fi

# -----------------------------------------------------------------------
# claim-recipient consistency (informational). Active claims whose
# recipient has been revoked are converged by the worker's
# ShareReconciliationJob after boot — surface the count, don't fail.
# -----------------------------------------------------------------------
echo "-- claim-recipient consistency"
stale_active=$(psql_t "SELECT COUNT(*) FROM share_claims c JOIN share_recipients r ON r.id = c.recipient_id WHERE c.revoked_at IS NULL AND c.expires_at > now() AND r.revoked_at IS NOT NULL")
if [ "${stale_active:-0}" != "0" ]; then
  echo "   note: $stale_active active claim(s) belong to revoked recipients — worker reconciliation will revoke them on next tick"
fi

# -----------------------------------------------------------------------
# access-request integrity (migration 017). share_access_requests is
# MUTABLE (status transitions); the append-only audit ledger holds the
# decision history. Hard failures (exit 5) are true broken relationships;
# soft mismatches the worker's AccessRequestCleanupJob converges after boot
# are surfaced as notes.
# -----------------------------------------------------------------------
echo "-- orphan-access-requests"
orphan_requests=$(psql_t "SELECT COUNT(*) FROM share_access_requests ar LEFT JOIN shares s ON s.id = ar.share_id WHERE s.id IS NULL")
if [ "${orphan_requests:-0}" != "0" ]; then
  fail_at "FOUND $orphan_requests orphan share_access_requests (no parent share)" 5
fi
# recipient_id is nullable (ON DELETE SET NULL) — only NON-NULL values must
# resolve to a recipient row.
echo "-- access-request recipient-fk integrity"
ar_bad_rcpt=$(psql_t "SELECT COUNT(*) FROM share_access_requests ar LEFT JOIN share_recipients r ON r.id = ar.recipient_id WHERE ar.recipient_id IS NOT NULL AND r.id IS NULL")
if [ "${ar_bad_rcpt:-0}" != "0" ]; then
  fail_at "FOUND $ar_bad_rcpt share_access_requests with a dangling recipient_id" 5
fi
# Approved requests should normally carry a recipient link. A NULL link is
# the "approved request whose recipient state is missing" case the worker's
# AccessRequestCleanupJob converges (it supersedes them with
# reason=recipient_missing). Informational here, not a hard failure.
echo "-- access-request approval consistency"
approved_no_recipient=$(psql_t "SELECT COUNT(*) FROM share_access_requests ar JOIN shares s ON s.id = ar.share_id WHERE ar.status = 'approved' AND ar.recipient_id IS NULL")
if [ "${approved_no_recipient:-0}" != "0" ]; then
  echo "   note: $approved_no_recipient approved access_request(s) have no recipient link — worker reconciliation will supersede them (recipient_missing) on next tick"
fi
# Approved requests whose linked recipient is now revoked — the owner later
# revoked access. Expected and informational.
approved_revoked=$(psql_t "SELECT COUNT(*) FROM share_access_requests ar JOIN share_recipients r ON r.id = ar.recipient_id WHERE ar.status = 'approved' AND r.revoked_at IS NOT NULL")
if [ "${approved_revoked:-0}" != "0" ]; then
  echo "   note: $approved_revoked approved access_request(s) point at a now-revoked recipient (access later withdrawn)"
fi
# Stale pending requests (past TTL, or whose recipient is already active) are
# converged by the worker's AccessRequestCleanupJob after boot.
stale_pending=$(psql_t "SELECT COUNT(*) FROM share_access_requests WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= now()")
if [ "${stale_pending:-0}" != "0" ]; then
  echo "   note: $stale_pending pending access_request(s) past TTL — worker cleanup will expire them on next tick"
fi
pending_with_recipient=$(psql_t "SELECT COUNT(*) FROM share_access_requests ar JOIN share_recipients r ON r.share_id = ar.share_id AND r.email_normalized = ar.requester_email_normalized WHERE ar.status = 'pending' AND r.revoked_at IS NULL")
if [ "${pending_with_recipient:-0}" != "0" ]; then
  echo "   note: $pending_with_recipient pending access_request(s) already map to an active recipient — worker cleanup will supersede them"
fi

# -----------------------------------------------------------------------
# audit-outbox — append-only audit ledger + its dispatch queue must be
# present; report pending (undispatched) outbox rows the worker will
# flush after boot.
# -----------------------------------------------------------------------
echo "-- audit-outbox"
pending_outbox=$(psql_t "SELECT COUNT(*) FROM domain_outbox WHERE dispatched_at IS NULL" 2>/dev/null || echo "")
if [ -z "$pending_outbox" ]; then
  fail_at "could not read domain_outbox — audit dispatch queue missing" 4
else
  echo "   pending (undispatched) outbox rows: $pending_outbox (worker flushes these after boot)"
fi

# -----------------------------------------------------------------------
# blob ↔ share_objects (forward: row → file on disk)
# -----------------------------------------------------------------------
echo "-- blob forward (row → file)"
missing=0
scanned=0
if [ -d "$stage_root" ]; then
  while IFS= read -r key; do
    [ -z "$key" ] && continue
    scanned=$((scanned+1))
    if [ ! -e "$stage_root/$key" ]; then
      missing=$((missing+1))
    fi
  done < <(psql_t "SELECT storage_key FROM share_objects LIMIT 5000")
  if [ "$missing" -gt 0 ]; then
    fail_at "MISSING $missing stage blobs under $stage_root (of $scanned share_objects rows scanned)" 5
  fi
fi

# -----------------------------------------------------------------------
# blob ↔ share_objects (backward: file on disk → row).
# Orphan blobs are not always terminal — the worker's SharePurgeJob
# will remove any blob whose share is purge-pending — but they are
# signal. Default threshold is 0; raise VERIFY_MAX_ORPHAN_BLOBS to
# tolerate up to N orphans in an intentionally mid-purge archive.
# -----------------------------------------------------------------------
echo "-- blob backward (file → row)"
if [ -d "$stage_root" ]; then
  known="$(mktemp)"
  onfs="$(mktemp)"
  trap 'rm -f "$known" "$onfs"' EXIT
  psql "$DATABASE_URL" -tAc "SELECT storage_key FROM share_objects" | sort -u > "$known"
  # List top-level entries under stage_root (each share_object is a
  # single flat file; the exact convention is set by ShareStageEngine).
  find "$stage_root" -maxdepth 1 -mindepth 1 -type f -printf '%f\n' 2>/dev/null | sort -u > "$onfs"
  orphan_blobs=$(comm -23 "$onfs" "$known" | wc -l)
  if [ "${orphan_blobs:-0}" -gt "$max_orphan" ]; then
    fail_at "FOUND $orphan_blobs orphan stage blobs (no share_objects row; threshold=$max_orphan)" 5
  elif [ "${orphan_blobs:-0}" -gt 0 ]; then
    echo "   note: $orphan_blobs orphan blob(s) present (within VERIFY_MAX_ORPHAN_BLOBS=$max_orphan)"
  fi
fi

# -----------------------------------------------------------------------
# vault forward (row → file) — each file_objects row must have a
# corresponding blob under BOX_STORAGE_ROOT/{box_id}/{storage_key}.
# Join with file_entries to recover the box_id; the join is done in
# SQL so we only issue one query.
# -----------------------------------------------------------------------
echo "-- vault forward (file_objects → file-on-disk)"
missing_vault=0
scanned_vault=0
if [ -d "$box_root" ]; then
  while IFS='|' read -r box_id storage_key; do
    [ -z "$box_id" ] && continue
    scanned_vault=$((scanned_vault+1))
    if [ ! -e "$box_root/$box_id/$storage_key" ]; then
      missing_vault=$((missing_vault+1))
    fi
  done < <(psql "$DATABASE_URL" -tAc \
    "SELECT fe.box_id || '|' || fo.storage_key
       FROM file_objects fo
       JOIN file_entries fe ON fe.id = fo.file_entry_id
       LIMIT 5000")
  if [ "$missing_vault" -gt 0 ]; then
    fail_at "MISSING $missing_vault vault blobs under $box_root (of $scanned_vault file_objects rows scanned)" 5
  fi
fi

# -----------------------------------------------------------------------
# vault backward (file → row). Vault blobs live at
# {box_id}/{storage_key}; list up to 10_000 of them and diff against
# the known set. Tolerate up to VERIFY_MAX_ORPHAN_VAULT_BLOBS so an
# intentionally mid-purge archive can still verify, but default to 0
# because vault loss is unrecoverable and orphan blobs are a stronger
# signal here than on the stage side.
# -----------------------------------------------------------------------
echo "-- vault backward (file → file_objects)"
if [ -d "$box_root" ]; then
  known_vault="$(mktemp)"
  onfs_vault="$(mktemp)"
  trap 'rm -f "$known" "$onfs" "$known_vault" "$onfs_vault"' EXIT
  psql "$DATABASE_URL" -tAc \
    "SELECT fe.box_id || '/' || fo.storage_key
       FROM file_objects fo
       JOIN file_entries fe ON fe.id = fo.file_entry_id" \
    | sort -u > "$known_vault"
  # Two-level-deep files only: {box_id}/{storage_key}. Subdirectories
  # below that are not part of the vault's storage contract; if they
  # appear it's unrelated data and we shouldn't flag on it.
  find "$box_root" -mindepth 2 -maxdepth 2 -type f -printf '%P\n' 2>/dev/null \
    | sort -u > "$onfs_vault"
  orphan_vault=$(comm -23 "$onfs_vault" "$known_vault" | wc -l | tr -d ' ')
  if [ "${orphan_vault:-0}" -gt "$max_orphan_vault" ]; then
    fail_at "FOUND $orphan_vault orphan vault blobs (no file_objects row; threshold=$max_orphan_vault)" 5
  elif [ "${orphan_vault:-0}" -gt 0 ]; then
    echo "   note: $orphan_vault orphan vault blob(s) present (within VERIFY_MAX_ORPHAN_VAULT_BLOBS=$max_orphan_vault)"
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "restore-verify: OK"
fi
exit "$fail"
