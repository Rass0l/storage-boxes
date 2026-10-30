package domain

import "time"

const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityElevated = "elevated"
	SeverityHigh     = "high"
)

type RiskSignal struct {
	ID          string
	SignalType  string
	Severity    string
	SubjectType string
	SubjectID   string
	ActorID     string
	Metadata    map[string]any
	CreatedAt   time.Time
}
