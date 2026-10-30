package infra

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

type MemoryAuditRepository struct {
	mu     sync.RWMutex
	events []domain.AuditEvent
}

var _ app.AuditRepository = (*MemoryAuditRepository)(nil)

func NewMemoryAuditRepository() *MemoryAuditRepository { return &MemoryAuditRepository{} }

func (r *MemoryAuditRepository) Put(ctx context.Context, event domain.AuditEvent) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *MemoryAuditRepository) ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.AuditEvent, error) {
	return r.List(ctx, app.AuditQuery{SubjectType: subjectType, SubjectID: subjectID})
}

func (r *MemoryAuditRepository) List(ctx context.Context, q app.AuditQuery) ([]domain.AuditEvent, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.AuditEvent{}
	for _, evt := range r.events {
		if q.SubjectType != "" && evt.SubjectType != q.SubjectType {
			continue
		}
		if q.SubjectID != "" && evt.SubjectID != q.SubjectID {
			continue
		}
		if q.EventType != "" && evt.EventType != q.EventType {
			continue
		}
		if q.ActorID != "" && evt.ActorID != q.ActorID {
			continue
		}
		if !q.Since.IsZero() && evt.OccurredAt.Before(q.Since) {
			continue
		}
		out = append(out, evt)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// MemoryOutbox is an in-memory OutboxRepository used by tests and the memory
// runtime. It preserves the same claim/dispatch semantics as the pg version.
type MemoryOutbox struct {
	mu      sync.Mutex
	records []outboxRow
}

type outboxRow struct {
	id          string
	topic       string
	payload     []byte
	attempts    int
	availableAt time.Time
	dispatched  bool
}

var _ app.OutboxRepository = (*MemoryOutbox)(nil)

func NewMemoryOutbox() *MemoryOutbox { return &MemoryOutbox{} }

func (o *MemoryOutbox) Enqueue(ctx context.Context, r domain.OutboxRecord) error {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, outboxRow{id: r.ID, topic: r.Topic, payload: r.Payload, availableAt: time.Now().UTC()})
	return nil
}

func (o *MemoryOutbox) Claim(ctx context.Context, now time.Time, limit int) ([]domain.OutboxRecord, error) {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	claimed := []domain.OutboxRecord{}
	for i := range o.records {
		if len(claimed) >= limit {
			break
		}
		r := &o.records[i]
		if r.dispatched {
			continue
		}
		if r.availableAt.After(now) {
			continue
		}
		r.attempts++
		claimed = append(claimed, domain.OutboxRecord{ID: r.id, Topic: r.topic, Payload: r.payload})
	}
	return claimed, nil
}

func (o *MemoryOutbox) MarkDispatched(ctx context.Context, id string) error {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.records {
		if o.records[i].id == id {
			o.records[i].dispatched = true
		}
	}
	return nil
}

func (o *MemoryOutbox) MarkFailed(ctx context.Context, id string, backoff time.Duration) error {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.records {
		if o.records[i].id == id {
			o.records[i].availableAt = time.Now().UTC().Add(backoff)
		}
	}
	return nil
}

// MemoryRiskSignals stores risk signals for tests.
type MemoryRiskSignals struct {
	mu      sync.RWMutex
	signals []domain.RiskSignal
}

var _ app.RiskSignalRepository = (*MemoryRiskSignals)(nil)

func NewMemoryRiskSignals() *MemoryRiskSignals { return &MemoryRiskSignals{} }

func (r *MemoryRiskSignals) PutSignal(ctx context.Context, s domain.RiskSignal) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, s)
	return nil
}

func (r *MemoryRiskSignals) ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.RiskSignal, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.RiskSignal{}
	for _, s := range r.signals {
		if s.SubjectType == subjectType && s.SubjectID == subjectID {
			out = append(out, s)
		}
	}
	return out, nil
}
