DROP TRIGGER IF EXISTS share_access_events_no_update ON share_access_events;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS prevent_append_only_mutation();
DROP TABLE IF EXISTS risk_signals;
DROP TABLE IF EXISTS domain_outbox;
DROP TABLE IF EXISTS audit_events;
