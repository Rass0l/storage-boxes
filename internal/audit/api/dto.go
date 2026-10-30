package api

type AuditEventResponse struct {
	ID          string         `json:"id"`
	EventType   string         `json:"event_type"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	ActorID     string         `json:"actor_id,omitempty"`
	OccurredAt  string         `json:"occurred_at,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type AuditEventPageResponse struct {
	Items      []AuditEventResponse `json:"items"`
	NextCursor string               `json:"next_cursor,omitempty"`
}
