#!/usr/bin/env bash
# backup.sh — production-oriented snapshot of the three state sources the
# platform owns: Postgres (metadata + audit), BOX_STORAGE_ROOT (vault
# blobs), and SHARE_STAGE_ROOT (staged share payloads).
#
# Usage:
#   DEST=/backups/$(date +%F)  bash scripts/backup.sh
#   RETAIN_DAYS=14              bash scripts/backup.sh   # prune older
#
# Env contract:
#   DATABASE_URL      — required; passed to pg_dump
#   BOX_STORAGE_ROOT  — path to vault blobs (default ./.box-storage)
#   SHARE_STAGE_ROOT  — path to share stage (default ./.share-stage)
#
# Stop application writers and purge workers before taking this multi-source
# snapshot. Restore with scripts/restore.sh; this is a custom-format pg_dump,
# not a SQL file to pipe into psql. See the recovery runbook.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL required}"
dest="${DEST:-./backups/$(date +%F_%H%M%S)}"
box_root="${BOX_STORAGE_ROOT:-./.box-storage}"
stage_root="${SHARE_STAGE_ROOT:-./.share-stage}"
retain="${RETAIN_DAYS:-7}"

mkdir -p "$dest"
echo "writing backup to $dest"

# Dump Postgres first. --no-owner so the restore target can belong to a
# different PG role. --format=custom lets the restore pick subsets.
pg_dump --no-owner --format=custom "$DATABASE_URL" > "$dest/postgres.dump"

# Capture blobs AFTER the dump while writers and purge workers remain stopped.
# A concurrent purge could delete a blob whose row IS in the earlier dump.
# Atomic file writes alone do not make this cross-source snapshot consistent.
#
# Archive format: we tar the CONTENTS of the root (`-C root .`) rather
# than the root itself (`-C dirname(root) basename(root)`). That keeps
# the archive path-agnostic — restore.sh can drop it into whatever
# BOX_STORAGE_ROOT / SHARE_STAGE_ROOT the target uses, even when the
# source and target basenames differ (`/var/lib/boxes` vs
# `/opt/storage-boxes/blobs`). restore.sh also handles legacy
# archives taken with the old layout.
if [ -d "$box_root" ]; then
  tar -C "$box_root" -czf "$dest/box_storage.tgz" .
fi

if [ -d "$stage_root" ]; then
  tar -C "$stage_root" -czf "$dest/share_stage.tgz" .
fi

# Record a manifest so restore.sh / restore-verify.sh can check we're
# looking at a complete, uncorrupted archive. Keys are source-friendly
# (underscore-separated, `sha256_<file>`) so restore.sh can just
# `source manifest.env`. Migration watermark is the highest numeric
# migrations file shipped at backup time — restore.sh refuses to run
# if the watermark exceeds the target code's migrations directory,
# since that would silently install schema we don't know about.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
migrations_dir="$(dirname "$(realpath "$0")")/../migrations"
high_mig="$(ls "$migrations_dir"/*.up.sql 2>/dev/null | awk -F/ '{print $NF}' | sort | tail -n1 || true)"
high_mig_num="$(printf '%s' "$high_mig" | sed -E 's/^0*([0-9]+)_.*/\1/;t;s/.*//')"
{
  echo "created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "database_url_redacted=redacted"
  echo "box_storage_root=$box_root"
  echo "share_stage_root=$stage_root"
  echo "migration_watermark=${high_mig:-unknown}"
  echo "migration_watermark_num=${high_mig_num:-0}"
  for f in postgres.dump box_storage.tgz share_stage.tgz; do
    [ -f "$dest/$f" ] || continue
    # Map filename to a shell-legal key: "postgres.dump" → "postgres_dump".
    key="$(printf '%s' "$f" | tr '.-' '__')"
    echo "sha256_${key}=$(sha256 "$dest/$f")"
  done
} > "$dest/manifest.env"

# Prune older backups.
parent="$(dirname "$dest")"
if [ -d "$parent" ]; then
  find "$parent" -maxdepth 1 -mindepth 1 -type d -mtime "+$retain" -exec rm -rf {} +
fi

echo "backup complete"
