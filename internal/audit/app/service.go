package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
)

// AuditService records business audit events and exposes query helpers.
// Record() is always append-only; callers may query by subject, actor, or
// event-type. The service transparently writes a matching outbox record so
// downstream projections / SIEM exporters can dispatch asynchronously.
type AuditService interface {
	Record(ctx context.Context, event domain.AuditEvent) error
	List(ctx context.Context, q AuditQuery) ([]domain.AuditEvent, error)
	RecordSignal(ctx context.Context, signal domain.RiskSignal) error
}

// AuditRepository is the persistence contract for audit_events rows.
type AuditRepository interface {
	Put(ctx context.Context, event domain.AuditEvent) error
	ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.AuditEvent, error)
	List(ctx context.Context, q AuditQuery) ([]domain.AuditEvent, error)
}

// OutboxRepository stages domain_outbox rows for async dispatch.
type OutboxRepository interface {
	Enqueue(ctx context.Context, record domain.OutboxRecord) error
	Claim(ctx context.Context, now time.Time, limit int) ([]domain.OutboxRecord, error)
	MarkDispatched(ctx context.Context, id string) error
	MarkFailed(ctx context.Context, id string, backoff time.Duration) error
}

// RiskSignalRepository persists risk_signals rows.
type RiskSignalRepository interface {
	PutSignal(ctx context.Context, signal domain.RiskSignal) error
	ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.RiskSignal, error)
}

// EventRecorder is the thin interface callers use when they only need to
// publish a domain event without going through the audit path (rare).
type EventRecorder interface {
	RecordDomainEvent(ctx context.Context, topic string, payload []byte) error
}

// Deps bundles the service's collaborators.
type Deps struct {
	Repo    AuditRepository
	Outbox  OutboxRepository
	Signals RiskSignalRepository
	Clock   clock.Clock
	IDs     ids.IDGenerator
}

// Service is the concrete AuditService implementation.
type Service struct {
	deps Deps
}

var _ AuditService = (*Service)(nil)

func NewService(deps Deps) *Service {
	if deps.Clock == nil {
		deps.Clock = clock.RealClock{}
	}
	if deps.IDs == nil {
		deps.IDs = ids.RandomGenerator{}
	}
	return &Service{deps: deps}
}

// Record persists an audit event and stages an outbox row for downstream
// projections. Both writes must succeed for the record to be acknowledged.
func (s *Service) Record(ctx context.Context, event domain.AuditEvent) error {
	if event.EventType == "" {
		return errors.New("audit: event_type required")
	}
	if event.ID == "" {
		event.ID = s.deps.IDs.New("aud")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.deps.Clock.Now().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	if err := s.deps.Repo.Put(ctx, event); err != nil {
		return err
	}
	if s.deps.Outbox != nil {
		payload, _ := json.Marshal(event)
		_ = s.deps.Outbox.Enqueue(ctx, domain.OutboxRecord{
			ID:      s.deps.IDs.New("out"),
			Topic:   event.EventType,
			Payload: payload,
		})
	}
	return nil
}

// List returns audit events matching q, newest first.
func (s *Service) List(ctx context.Context, q AuditQuery) ([]domain.AuditEvent, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	return s.deps.Repo.List(ctx, q)
}

// RecordSignal persists a risk signal. Signals are advisory: a failure here
// must not block the underlying business operation, but we return the error
// so callers can log it.
func (s *Service) RecordSignal(ctx context.Context, signal domain.RiskSignal) error {
	if s.deps.Signals == nil {
		return nil
	}
	if signal.ID == "" {
		signal.ID = s.deps.IDs.New("risk")
	}
	if signal.CreatedAt.IsZero() {
		signal.CreatedAt = s.deps.Clock.Now().UTC()
	}
	if signal.Severity == "" {
		signal.Severity = domain.SeverityInfo
	}
	if signal.Metadata == nil {
		signal.Metadata = map[string]any{}
	}
	return s.deps.Signals.PutSignal(ctx, signal)
}
