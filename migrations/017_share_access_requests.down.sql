-- 017_share_access_requests.down.sql
DROP INDEX IF EXISTS idx_share_access_requests_recipient;
DROP INDEX IF EXISTS idx_share_access_requests_pending;
DROP INDEX IF EXISTS idx_share_access_requests_share;
DROP INDEX IF EXISTS uq_share_access_requests_pending;
DROP TABLE IF EXISTS share_access_requests;
