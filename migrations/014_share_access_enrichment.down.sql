DROP INDEX IF EXISTS idx_audit_events_subject;
DROP INDEX IF EXISTS idx_audit_events_actor;
DROP INDEX IF EXISTS idx_risk_signals_subject;

ALTER TABLE risk_signals
  DROP COLUMN IF EXISTS actor_id,
  DROP COLUMN IF EXISTS subject_id,
  DROP COLUMN IF EXISTS subject_type;

ALTER TABLE share_access_events
  DROP COLUMN IF EXISTS country_code,
  DROP COLUMN IF EXISTS risk_score;
