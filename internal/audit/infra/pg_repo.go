package infra

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

// PGAuditRepository persists audit events into the append-only audit_events
// table. Update/delete is blocked by the table trigger in migration 007, so
// any mistaken re-Put of an event surfaces as a DB error rather than a silent
// overwrite.
type PGAuditRepository struct{ pool *pgxpool.Pool }

var _ app.AuditRepository = (*PGAuditRepository)(nil)

func NewPGAuditRepository(pool *pgxpool.Pool) *PGAuditRepository {
	return &PGAuditRepository{pool: pool}
}

func (r *PGAuditRepository) Put(ctx context.Context, evt domain.AuditEvent) error {
	meta, err := json.Marshal(evt.Metadata)
	if err != nil {
		return err
	}
	var actor any
	if evt.ActorID != "" {
		actor = evt.ActorID
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_events(id, event_type, subject_type, subject_id, actor_id, metadata, occurred_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
		evt.ID, evt.EventType, evt.SubjectType, evt.SubjectID, actor, meta, evt.OccurredAt)
	return err
}

func (r *PGAuditRepository) ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.AuditEvent, error) {
	return r.List(ctx, app.AuditQuery{SubjectType: subjectType, SubjectID: subjectID, Limit: 200})
}

func (r *PGAuditRepository) List(ctx context.Context, q app.AuditQuery) ([]domain.AuditEvent, error) {
	var where []string
	var args []any
	i := 1
	add := func(sql string, v any) {
		where = append(where, strings.ReplaceAll(sql, "?", placeholder(i)))
		args = append(args, v)
		i++
	}
	if q.SubjectType != "" {
		add("subject_type = ?", q.SubjectType)
	}
	if q.SubjectID != "" {
		add("subject_id = ?", q.SubjectID)
	}
	if q.EventType != "" {
		add("event_type = ?", q.EventType)
	}
	if q.ActorID != "" {
		add("actor_id = ?", q.ActorID)
	}
	if !q.Since.IsZero() {
		add("occurred_at >= ?", q.Since)
	}
	sql := `SELECT id, event_type, subject_type, subject_id, COALESCE(actor_id,''), metadata, occurred_at
	        FROM audit_events`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	sql += " ORDER BY occurred_at DESC LIMIT " + itoa(limit)
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AuditEvent{}
	for rows.Next() {
		var e domain.AuditEvent
		var metaRaw []byte
		var actor string
		if err := rows.Scan(&e.ID, &e.EventType, &e.SubjectType, &e.SubjectID, &actor, &metaRaw, &e.OccurredAt); err != nil {
			return nil, err
		}
		e.ActorID = actor
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &e.Metadata)
		}
		if e.Metadata == nil {
			e.Metadata = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PGOutboxRepository persists domain_outbox rows with a classic FOR UPDATE
// SKIP LOCKED claim semantic. Dispatched rows are marked with
// dispatched_at so redelivery is idempotent across worker restarts.
type PGOutboxRepository struct{ pool *pgxpool.Pool }

var _ app.OutboxRepository = (*PGOutboxRepository)(nil)

func NewPGOutboxRepository(pool *pgxpool.Pool) *PGOutboxRepository {
	return &PGOutboxRepository{pool: pool}
}

func (r *PGOutboxRepository) Enqueue(ctx context.Context, rec domain.OutboxRecord) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO domain_outbox(id, topic, payload)
		VALUES ($1, $2, $3)`,
		rec.ID, rec.Topic, rec.Payload)
	return err
}

func (r *PGOutboxRepository) Claim(ctx context.Context, now time.Time, limit int) ([]domain.OutboxRecord, error) {
	rows, err := r.pool.Query(ctx, `
		WITH claimed AS (
		  SELECT id FROM domain_outbox
		  WHERE dispatched_at IS NULL AND available_at <= $1
		  ORDER BY available_at
		  FOR UPDATE SKIP LOCKED
		  LIMIT $2
		)
		UPDATE domain_outbox o
		  SET attempts = o.attempts + 1
		  FROM claimed
		  WHERE o.id = claimed.id
		  RETURNING o.id, o.topic, o.payload`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.OutboxRecord{}
	for rows.Next() {
		var rec domain.OutboxRecord
		if err := rows.Scan(&rec.ID, &rec.Topic, &rec.Payload); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *PGOutboxRepository) MarkDispatched(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE domain_outbox SET dispatched_at = now() WHERE id = $1`, id)
	return err
}

func (r *PGOutboxRepository) MarkFailed(ctx context.Context, id string, backoff time.Duration) error {
	_, err := r.pool.Exec(ctx, `UPDATE domain_outbox SET available_at = now() + ($2::text || ' milliseconds')::interval WHERE id = $1`, id, itoa(int(backoff/time.Millisecond)))
	return err
}

// PGRiskSignalRepository persists risk_signals rows.
type PGRiskSignalRepository struct{ pool *pgxpool.Pool }

var _ app.RiskSignalRepository = (*PGRiskSignalRepository)(nil)

func NewPGRiskSignalRepository(pool *pgxpool.Pool) *PGRiskSignalRepository {
	return &PGRiskSignalRepository{pool: pool}
}

func (r *PGRiskSignalRepository) PutSignal(ctx context.Context, s domain.RiskSignal) error {
	meta, err := json.Marshal(s.Metadata)
	if err != nil {
		return err
	}
	var subjectType, subjectID, actor any
	if s.SubjectType != "" {
		subjectType = s.SubjectType
	}
	if s.SubjectID != "" {
		subjectID = s.SubjectID
	}
	if s.ActorID != "" {
		actor = s.ActorID
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO risk_signals(id, signal_type, severity, subject_type, subject_id, actor_id, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.ID, s.SignalType, s.Severity, subjectType, subjectID, actor, meta, s.CreatedAt)
	return err
}

func (r *PGRiskSignalRepository) ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.RiskSignal, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, signal_type, severity, COALESCE(subject_type,''), COALESCE(subject_id,''), COALESCE(actor_id,''), metadata, created_at
		FROM risk_signals
		WHERE subject_type = $1 AND subject_id = $2
		ORDER BY created_at DESC`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.RiskSignal{}
	for rows.Next() {
		var s domain.RiskSignal
		var metaRaw []byte
		if err := rows.Scan(&s.ID, &s.SignalType, &s.Severity, &s.SubjectType, &s.SubjectID, &s.ActorID, &metaRaw, &s.CreatedAt); err != nil {
			return nil, err
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &s.Metadata)
		}
		if s.Metadata == nil {
			s.Metadata = map[string]any{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func placeholder(i int) string { return "$" + itoa(i) }
