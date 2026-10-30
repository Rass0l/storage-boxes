DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_absolute_expires_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS absolute_expires_at;
