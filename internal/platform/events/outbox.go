package events

import "time"

type OutboxMessage struct {
	ID           string
	Topic        string
	Payload      []byte
	Attempts     int
	AvailableAt  time.Time
	DispatchedAt *time.Time
}
