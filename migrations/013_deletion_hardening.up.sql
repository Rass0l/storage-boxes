-- 013_deletion_hardening.up.sql
-- Adds soft-delete + purge-request columns so box/file/share deletion can be
-- staged and finalized by the worker. Status transitions: active → deleting
-- (deleted_at stamped, purge_requested_at stamped) → purged (row removed).

ALTER TABLE boxes
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS purge_requested_at TIMESTAMPTZ NULL;

ALTER TABLE file_entries
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE shares
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS purge_requested_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS created_by TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_boxes_purge_pending
  ON boxes(purge_requested_at)
  WHERE purge_requested_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_shares_status_expires
  ON shares(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_shares_purge_pending
  ON shares(purge_requested_at)
  WHERE purge_requested_at IS NOT NULL;
