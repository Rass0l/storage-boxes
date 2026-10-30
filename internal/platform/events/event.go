package events

import "time"

type DomainEvent struct {
	ID          string
	Type        string
	AggregateID string
	Version     int
	OccurredAt  time.Time
	Payload     map[string]any
}

type EventBus interface {
	Publish(event DomainEvent) error
}
