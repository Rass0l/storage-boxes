package api

import (
	"context"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
)

// AttachAudit installs an audit sink on the vault service so box create /
// delete / unlock events become audit_events rows. Safe with nil audit.
func AttachAudit(svc *vaultapp.Service, audit auditapp.AuditService) {
	if svc == nil || audit == nil {
		return
	}
	svc.SetAuditSink(vaultapp.AuditSinkFunc(func(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any) {
		_ = audit.Record(ctx, auditdomain.AuditEvent{
			EventType:   eventType,
			SubjectType: subjectType,
			SubjectID:   subjectID,
			ActorID:     actorID,
			Metadata:    meta,
		})
	}))
}
