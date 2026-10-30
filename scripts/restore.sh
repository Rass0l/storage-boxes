#!/usr/bin/env bash
# restore.sh — apply a storage-boxes backup archive to an empty (or
# truncated) target environment. Enforces the recovery ordering and
# gating rules documented in docs/implementation/backup-restore.md and
# DEPLOYMENT.md.
#
# Stages:
#   1. Integrity: verify manifest.env SHA-256 for every artifact.
#   2. Watermark: refuse if the archive's migration watermark is
#      higher than the target code's migrations directory.
#   3. Empty-target guard (skippable with FORCE=1).
#   4. pg_restore (metadata, shares, recipients, claims, audit, outbox).
#   5. Untar SHARE_STAGE_ROOT.
#   6. Untar BOX_STORAGE_ROOT.
#   7. scripts/restore-verify.sh (row counts, triggers, blob cross-check).
#   8. Optional: wait for the worker's first ShareReconciliationJob tick
#      before exiting 0 — so callers can use `restore.sh && start-gateway`
#      safely.
#
# Usage:
#   SRC=/backups/2026-04-17 bash scripts/restore.sh
#   DRY_RUN=1 SRC=...            # no writes
#   FORCE=1 SRC=...               # allow restore on a non-empty target
#   WORKER_URL=http://worker:8083 RESTORE_WAIT_FOR_WORKER=1 SRC=...
#     # the script will not exit until the worker's `reconciled` counter
#     # has advanced (default timeout 120s, override with WORKER_WAIT_SECONDS).
#
# Env contract:
#   DATABASE_URL          — required.
#   SRC                   — required; directory containing backup archive.
#   BOX_STORAGE_ROOT      — default ./.box-storage
#   SHARE_STAGE_ROOT      — default ./.share-stage
#   MIGRATIONS_DIR        — auto-detected relative to this script; set
#                           explicitly if running from a packaged artifact.
#   FORCE                 — "1" to overwrite a non-empty DB.
#   DRY_RUN               — "1" to log planned actions without mutating.
#   SKIP_INTEGRITY_CHECK  — "1" to bypass manifest SHA-256 check
#                           (not recommended — only when the archive was
#                           taken before manifest support was added).
#   WORKER_URL            — if set with RESTORE_WAIT_FOR_WORKER=1, poll
#                           $WORKER_URL/api/v1/worker/sweep-stats until
#                           the reconcile counter advances.
#   RESTORE_WAIT_FOR_WORKER — "1" to enable the worker-tick wait.
#   WORKER_WAIT_SECONDS   — default 120; how long to poll.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL required}"
: "${SRC:?SRC required (path to backup archive directory)}"

box_root="${BOX_STORAGE_ROOT:-./.box-storage}"
stage_root="${SHARE_STAGE_ROOT:-./.share-stage}"
dry="${DRY_RUN:-0}"
script_dir="$(dirname "$(realpath "$0")")"
migrations_dir="${MIGRATIONS_DIR:-${script_dir}/../migrations}"

[ -d "$SRC" ] || { echo "no such SRC: $SRC" >&2; exit 2; }
[ -f "$SRC/postgres.dump" ] || { echo "missing $SRC/postgres.dump" >&2; exit 2; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

run() {
  if [ "$dry" = "1" ]; then
    echo "DRY  $*"
  else
    echo "RUN  $*"
    "$@"
  fi
}

echo "==> restore from $SRC"

# -----------------------------------------------------------------------
# 1. Integrity — verify archive matches its manifest.
# -----------------------------------------------------------------------
manifest_watermark_num=0
manifest_watermark_name=""
if [ -f "$SRC/manifest.env" ]; then
  # Source the manifest into a *local subshell* so malformed lines can't
  # touch our environment. We re-read selected keys via grep afterwards.
  if [ "${SKIP_INTEGRITY_CHECK:-0}" != "1" ]; then
    echo "==> verifying manifest SHA-256"
    bad=0
    # Iterate sha256_* keys; each maps "_"-encoded filename back to the
    # archive file. e.g. sha256_postgres_dump → postgres.dump
    while IFS='=' read -r key want; do
      case "$key" in
        sha256_*) ;;
        *) continue ;;
      esac
      enc="${key#sha256_}"
      # Reverse the tr '.-' '__' mapping. Since we don't know the
      # original punctuation, try the known artifact names.
      f=""
      for candidate in postgres.dump box_storage.tgz share_stage.tgz; do
        c_key="$(printf '%s' "$candidate" | tr '.-' '__')"
        [ "$c_key" = "$enc" ] && { f="$candidate"; break; }
      done
      if [ -z "$f" ] || [ ! -f "$SRC/$f" ]; then
        echo "  !! manifest references unknown file for key $key" >&2
        bad=1
        continue
      fi
      got="$(sha256 "$SRC/$f")"
      if [ "$got" != "$want" ]; then
        echo "  !! $f: sha256 mismatch (want $want, got $got)" >&2
        bad=1
      else
        echo "  ok  $f"
      fi
    done < "$SRC/manifest.env"
    if [ "$bad" = "1" ]; then
      echo "archive integrity check failed" >&2
      exit 4
    fi
  else
    echo "!! skipping integrity check (SKIP_INTEGRITY_CHECK=1)"
  fi
  manifest_watermark_num="$(awk -F= '$1=="migration_watermark_num"{print $2}' "$SRC/manifest.env" | head -n1)"
  manifest_watermark_num="${manifest_watermark_num:-0}"
  manifest_watermark_name="$(awk -F= '$1=="migration_watermark"{print $2}' "$SRC/manifest.env" | head -n1)"
else
  if [ "${SKIP_INTEGRITY_CHECK:-0}" != "1" ]; then
    echo "!! no manifest.env; pass SKIP_INTEGRITY_CHECK=1 to restore an older archive" >&2
    exit 4
  fi
  echo "!! no manifest.env; integrity + watermark check skipped"
fi

# -----------------------------------------------------------------------
# 2. Watermark — archive must not exceed the target code's migrations.
#    Restoring a newer-schema dump onto older code would silently install
#    tables / triggers we can't interpret.
# -----------------------------------------------------------------------
if [ "$manifest_watermark_num" != "0" ] && [ -d "$migrations_dir" ]; then
  target_high="$(ls "$migrations_dir"/*.up.sql 2>/dev/null | awk -F/ '{print $NF}' | sort | tail -n1 || true)"
  target_high_num="$(printf '%s' "$target_high" | sed -E 's/^0*([0-9]+)_.*/\1/;t;s/.*//')"
  target_high_num="${target_high_num:-0}"
  echo "    archive migration watermark = ${manifest_watermark_num} (${manifest_watermark_name})"
  echo "    target code watermark       = ${target_high_num} (${target_high})"
  if [ "$manifest_watermark_num" -gt "$target_high_num" ]; then
    echo "archive was taken against migrations newer than this target ($manifest_watermark_num > $target_high_num)." >&2
    echo "refusing to restore; upgrade the target binaries first." >&2
    exit 5
  fi
fi

# -----------------------------------------------------------------------
# 3. Empty-target guard.
# -----------------------------------------------------------------------
if [ "${FORCE:-0}" != "1" ] && [ "$dry" != "1" ]; then
  # Use to_regclass so the query returns 0 cleanly on a schema-less
  # target (first-ever restore). Avoids the "missing table" error that
  # the previous COALESCE variant could still surface.
  count=$(psql "$DATABASE_URL" -tAc "SELECT CASE WHEN to_regclass('public.audit_events') IS NULL THEN 0 ELSE (SELECT COUNT(*) FROM audit_events) END" 2>/dev/null || echo 0)
  if [ "${count:-0}" != "0" ]; then
    echo "target database is non-empty (audit_events has ${count} rows). Set FORCE=1 to overwrite." >&2
    exit 3
  fi
fi

# -----------------------------------------------------------------------
# 4. pg_restore — schema + data. --clean/--if-exists so FORCE=1 replays
#    on top of prior state. --exit-on-error so a partial failure stops
#    before we untar blobs that wouldn't have matching rows.
# -----------------------------------------------------------------------
echo "==> restoring postgres dump"
run pg_restore --no-owner --clean --if-exists --exit-on-error -d "$DATABASE_URL" "$SRC/postgres.dump"

# -----------------------------------------------------------------------
# 5. Share stage. Unpacked before vault blobs so the verifier's
#    cross-check against share_objects.storage_key has something to
#    read on failure paths.
#
# Extraction goes through _extract-archive.sh so the archive contents
# always land at $stage_root, regardless of whether the archive was
# taken with the new content-style layout or a legacy named-top-dir
# layout whose basename doesn't match $stage_root.
# -----------------------------------------------------------------------
extract="${script_dir}/_extract-archive.sh"
if [ ! -x "$extract" ]; then
  echo "missing $extract" >&2
  exit 2
fi
if [ -f "$SRC/share_stage.tgz" ]; then
  echo "==> restoring share stage → $stage_root"
  if [ "$dry" = "1" ]; then
    echo "DRY  $extract $SRC/share_stage.tgz $stage_root"
  else
    "$extract" "$SRC/share_stage.tgz" "$stage_root"
  fi
fi

# -----------------------------------------------------------------------
# 6. Vault blobs.
# -----------------------------------------------------------------------
if [ -f "$SRC/box_storage.tgz" ]; then
  echo "==> restoring box storage → $box_root"
  if [ "$dry" = "1" ]; then
    echo "DRY  $extract $SRC/box_storage.tgz $box_root"
  else
    "$extract" "$SRC/box_storage.tgz" "$box_root"
  fi
fi

# -----------------------------------------------------------------------
# 7. Verify.
# -----------------------------------------------------------------------
verify="${script_dir}/restore-verify.sh"
if [ -x "$verify" ]; then
  echo "==> running restore verification"
  if [ "$dry" = "1" ]; then
    echo "DRY  $verify"
  else
    "$verify"
  fi
else
  echo "!! restore-verify.sh not executable; skipping" >&2
fi

# -----------------------------------------------------------------------
# 8. Optional worker-reconcile gate — matches the documented recovery
#    ordering. The restore script can't start services (that's
#    deployment-tool specific), but if the operator points us at an
#    already-running worker we poll sweep-stats until its `reconciled`
#    counter advances, so a CI restore→bring-up pipeline can chain
#    `scripts/restore.sh && start-gateway` without manual inspection.
# -----------------------------------------------------------------------
if [ "${RESTORE_WAIT_FOR_WORKER:-0}" = "1" ] && [ -n "${WORKER_URL:-}" ] && [ "$dry" != "1" ]; then
  wait_seconds="${WORKER_WAIT_SECONDS:-120}"
  echo "==> waiting up to ${wait_seconds}s for worker reconcile tick (${WORKER_URL})"
  end=$(( $(date +%s) + wait_seconds ))
  initial="$(curl -fsS "${WORKER_URL}/api/v1/worker/sweep-stats" 2>/dev/null | tr ',' '\n' | awk -F: '/reconciled/ {gsub(/[^0-9]/,"",$2); print $2}' | head -n1 || echo 0)"
  initial="${initial:-0}"
  echo "    initial reconciled=$initial"
  while :; do
    now=$(date +%s)
    if [ "$now" -ge "$end" ]; then
      echo "worker reconcile tick did not advance within ${wait_seconds}s" >&2
      exit 6
    fi
    current="$(curl -fsS "${WORKER_URL}/api/v1/worker/sweep-stats" 2>/dev/null | tr ',' '\n' | awk -F: '/reconciled/ {gsub(/[^0-9]/,"",$2); print $2}' | head -n1 || echo 0)"
    current="${current:-0}"
    if [ "$current" -gt "$initial" ]; then
      echo "    reconciled=$current (advanced; safe to start gateway + api)"
      break
    fi
    sleep 2
  done
fi

echo "==> restore complete"
if [ "${RESTORE_WAIT_FOR_WORKER:-0}" != "1" ]; then
  cat <<'EOF'
    Bring services up in order: worker → share-gateway → api/edge.
    Gate each step on the worker's /api/v1/worker/sweep-stats
    counters (reconciled, shares_purged, claims_expired) rather than
    on /readyz, which is a pg-reachability probe only. See
    docs/implementation/backup-restore.md.
EOF
fi
