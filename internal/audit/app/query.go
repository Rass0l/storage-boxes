package app

import "time"

// AuditQuery filters ListAuditEvents. All fields are optional and combine
// with AND semantics.
type AuditQuery struct {
	SubjectType string
	SubjectID   string
	EventType   string
	ActorID     string
	Since       time.Time
	Limit       int
}
