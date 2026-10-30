CREATE INDEX idx_audit_events_subject ON audit_events(subject_type, subject_id);
CREATE INDEX idx_audit_events_type ON audit_events(event_type);
CREATE INDEX idx_shares_expires_at ON shares(expires_at);
CREATE INDEX idx_domain_outbox_dispatch ON domain_outbox(dispatched_at, available_at);
