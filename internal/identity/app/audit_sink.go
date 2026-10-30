package app

import "context"

// AuditSink is the narrow hook the identity service exposes so that higher
// layers (cmd/api wiring) can plug in the audit service without pulling an
// audit dependency into identity/app. Nil-safe: when unset, the service
// records nothing.
type AuditSink interface {
	Emit(ctx context.Context, eventType, subjectID, actorID string, meta map[string]any)
}

// AuditSinkFunc adapts an ordinary function to AuditSink.
type AuditSinkFunc func(ctx context.Context, eventType, subjectID, actorID string, meta map[string]any)

func (f AuditSinkFunc) Emit(ctx context.Context, eventType, subjectID, actorID string, meta map[string]any) {
	f(ctx, eventType, subjectID, actorID, meta)
}

// SetAuditSink installs the audit hook. Safe to call multiple times; the
// latest sink wins. Passing nil disables emission.
func (s *Service) SetAuditSink(sink AuditSink) { s.auditSink = sink }

func (s *Service) emitAudit(ctx context.Context, eventType, subjectID, actorID string, meta map[string]any) {
	if s.auditSink == nil {
		return
	}
	if meta == nil {
		meta = map[string]any{}
	}
	s.auditSink.Emit(ctx, eventType, subjectID, actorID, meta)
}
