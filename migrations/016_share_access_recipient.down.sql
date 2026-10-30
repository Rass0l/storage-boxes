DROP INDEX IF EXISTS idx_share_access_events_recipient;
ALTER TABLE share_access_events DROP COLUMN IF EXISTS recipient_id;
