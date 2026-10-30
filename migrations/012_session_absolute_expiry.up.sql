-- 012_session_absolute_expiry.up.sql
-- Sessions now track an absolute hard deadline in addition to the sliding
-- idle deadline (`expires_at`). `absolute_expires_at` is set at issue time
-- and never advances; a sliding refresh must never push past it.

ALTER TABLE sessions
  ADD COLUMN absolute_expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days');

CREATE INDEX IF NOT EXISTS idx_sessions_absolute_expires_at ON sessions(absolute_expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
