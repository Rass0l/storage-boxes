DROP INDEX IF EXISTS idx_shares_purge_pending;
DROP INDEX IF EXISTS idx_shares_status_expires;
DROP INDEX IF EXISTS idx_boxes_purge_pending;

ALTER TABLE shares
  DROP COLUMN IF EXISTS created_by,
  DROP COLUMN IF EXISTS purge_requested_at,
  DROP COLUMN IF EXISTS revoked_at;

ALTER TABLE file_entries
  DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE boxes
  DROP COLUMN IF EXISTS purge_requested_at,
  DROP COLUMN IF EXISTS deleted_at;
