-- 014_share_access_enrichment.up.sql
-- Extend share access + risk signal rows with enrichment context that the
-- audit subsystem populates at record time. Append-only triggers on
-- share_access_events still apply.

ALTER TABLE share_access_events
  ADD COLUMN IF NOT EXISTS risk_score SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS country_code TEXT NULL;

ALTER TABLE risk_signals
  ADD COLUMN IF NOT EXISTS subject_type TEXT NULL,
  ADD COLUMN IF NOT EXISTS subject_id TEXT NULL,
  ADD COLUMN IF NOT EXISTS actor_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_risk_signals_subject
  ON risk_signals(subject_type, subject_id)
  WHERE subject_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_actor
  ON audit_events(actor_id, occurred_at DESC)
  WHERE actor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_subject
  ON audit_events(subject_type, subject_id, occurred_at DESC);
