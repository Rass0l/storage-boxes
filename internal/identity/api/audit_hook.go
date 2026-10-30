package api

import (
	"context"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
)

// AttachAudit wraps the identity service's Login method so successful and
// failed login attempts produce audit_events rows. The wrapper is installed
// via svc.SetAuditSink, which the identity service exposes specifically for
// this edge-of-package concern. Safe to call with a nil audit.
func AttachAudit(svc *identityapp.Service, audit auditapp.AuditService) {
	if svc == nil || audit == nil {
		return
	}
	svc.SetAuditSink(identityapp.AuditSinkFunc(func(ctx context.Context, eventType, subjectID, actorID string, meta map[string]any) {
		_ = audit.Record(ctx, auditdomain.AuditEvent{
			EventType:   eventType,
			SubjectType: auditdomain.SubjectTypeUser,
			SubjectID:   subjectID,
			ActorID:     actorID,
			Metadata:    meta,
		})
	}))
}
