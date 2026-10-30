package infra

import (
	"context"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

// NoopEventRecorder is a placeholder for EventRecorder that drops events.
// Retained for callers wired before the outbox pipeline existed; prefer
// EnqueueingRecorder in new code.
type NoopEventRecorder struct{}

var _ app.EventRecorder = NoopEventRecorder{}

func (NoopEventRecorder) RecordDomainEvent(ctx context.Context, topic string, payload []byte) error {
	_ = ctx
	_ = topic
	_ = payload
	return nil
}

// NoopOutbox satisfies OutboxRepository without persisting anything.
type NoopOutbox struct{}

var _ app.OutboxRepository = NoopOutbox{}

func (NoopOutbox) Enqueue(ctx context.Context, r domain.OutboxRecord) error {
	_ = ctx
	_ = r
	return nil
}
func (NoopOutbox) Claim(ctx context.Context, now time.Time, limit int) ([]domain.OutboxRecord, error) {
	_ = ctx
	_ = now
	_ = limit
	return nil, nil
}
func (NoopOutbox) MarkDispatched(ctx context.Context, id string) error { _ = ctx; _ = id; return nil }
func (NoopOutbox) MarkFailed(ctx context.Context, id string, backoff time.Duration) error {
	_ = ctx
	_ = id
	_ = backoff
	return nil
}
