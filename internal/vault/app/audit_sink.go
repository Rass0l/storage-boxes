package app

import "context"

// AuditSink lets higher layers (cmd/api wiring) receive vault audit events
// without dragging an audit dependency into this package. Nil-safe.
type AuditSink interface {
	Emit(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any)
}

type AuditSinkFunc func(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any)

func (f AuditSinkFunc) Emit(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any) {
	f(ctx, eventType, subjectType, subjectID, actorID, meta)
}

// SetAuditSink installs the audit hook.
func (s *Service) SetAuditSink(sink AuditSink) { s.auditSink = sink }

func (s *Service) emitAudit(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any) {
	if s.auditSink == nil {
		return
	}
	if meta == nil {
		meta = map[string]any{}
	}
	s.auditSink.Emit(ctx, eventType, subjectType, subjectID, actorID, meta)
}
