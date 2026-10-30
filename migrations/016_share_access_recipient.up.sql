-- 016_share_access_recipient.up.sql
-- Restricted-share deliveries are recorded on share_access_events but up
-- through migration 014 the row only carried IP/UA/risk. The recipient
-- that authorized the download was only reachable by reverse-joining
-- share_claims via the cookie hash — which the gateway can do live but
-- the recipient-scoped audit view cannot.
--
-- Add a nullable recipient_id column so every restricted delivery
-- (success, denial, and stream-interrupted) is durably attributable to
-- the recipient whose claim was in play. Public shares leave the
-- column NULL. The append-only trigger from migration 007 continues to
-- apply — we only INSERT into this table.
--
-- ON DELETE SET NULL so the foreign key stays sound when a recipient
-- row is hard-deleted as part of a share purge (`share_recipients`
-- rows are kept across normal lifecycle transitions, but FK cascades
-- land on them during share purge via share_id → share_recipients).

ALTER TABLE share_access_events
  ADD COLUMN IF NOT EXISTS recipient_id TEXT NULL
    REFERENCES share_recipients(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_share_access_events_recipient
  ON share_access_events(recipient_id, accessed_at DESC)
  WHERE recipient_id IS NOT NULL;
