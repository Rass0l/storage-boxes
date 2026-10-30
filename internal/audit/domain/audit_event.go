package domain

import "time"

type AuditEvent struct {
	ID          string
	EventType   string
	SubjectType string
	SubjectID   string
	ActorID     string
	OccurredAt  time.Time
	Metadata    map[string]any
}
