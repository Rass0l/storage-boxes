package app

import (
	"context"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ShareExpiryJob sweeps active shares whose ExpiresAt has passed and marks
// them expired + purge-requested. Idempotent: a share already in a
// terminal state is skipped.
type ShareExpiryJob struct {
	Shares app.ShareRepository
	Audit  auditapp.AuditService
}

// Run scans expired shares and transitions each to status=expired +
// purge_requested. Returns the number of rows touched.
func (j ShareExpiryJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := j.Shares.ListExpired(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	touched := 0
	for _, s := range rows {
		if s.Status != domain.StatusActive {
			continue
		}
		// purge_requested first (drops deliverability via IsDeliverable
		// in the same instant), status second. Terminal
		// `shares.expired` audit only fires after both writes converge;
		// a failure leaves the row retry-able on the next tick without
		// a lying audit record.
		if err := j.Shares.MarkPurgeRequested(ctx, s.ID, now); err != nil {
			continue
		}
		if err := j.Shares.UpdateStatus(ctx, s.ID, domain.StatusExpired, now); err != nil {
			continue
		}
		if j.Audit != nil {
			_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
				EventType:   auditdomain.EventShareExpired,
				SubjectType: auditdomain.SubjectTypeShare,
				SubjectID:   s.ID,
				Metadata:    map[string]any{"reason": "ttl"},
			})
		}
		touched++
	}
	return touched, nil
}

// SharePurgeJob finalizes revoked/expired shares by deleting their staged
// object bytes and share_object row. After purge succeeds the share is
// marked status=purged. Idempotent.
type SharePurgeJob struct {
	Shares  app.ShareRepository
	Objects app.ShareObjectStore
	Stage   app.StageEngine
	Audit   auditapp.AuditService
}

func (j SharePurgeJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := j.Shares.ListPurgeCandidates(ctx, limit)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, s := range rows {
		if j.runOne(ctx, s, now) {
			done++
		}
	}
	return done, nil
}

// runOne drives a single share toward `status=purged`. Returns true when
// the row reached the terminal state on this call. Used by BoxPurgeJob
// to push specific shares forward while finalizing a soft-deleted box.
func (j SharePurgeJob) runOne(ctx context.Context, s domain.Share, now time.Time) bool {
	if s.Status == domain.StatusPurged {
		return false
	}
	// Delete the stage object first. A failure here is not terminal:
	// we leave `purge_requested_at` set and return false, so the next
	// tick (of this job or of BoxPurgeJob) will retry. We do NOT flip
	// status to purged on partial failure — that would lie about the
	// on-disk state.
	obj, err := j.Objects.GetObject(ctx, s.ID)
	if err == nil && j.Stage != nil {
		if derr := j.Stage.Delete(ctx, s.ID, obj.StorageKey); derr != nil {
			return false
		}
		if derr := j.Objects.DeleteObject(ctx, s.ID); derr != nil {
			return false
		}
	}
	if err := j.Shares.UpdateStatus(ctx, s.ID, domain.StatusPurged, now); err != nil {
		return false
	}
	if j.Audit != nil {
		_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
			EventType:   auditdomain.EventSharePurged,
			SubjectType: auditdomain.SubjectTypeShare,
			SubjectID:   s.ID,
		})
	}
	return true
}

// OutboxDispatchJob claims pending outbox rows and marks them dispatched.
// Delivery to a real bus is plug-in via the Deliver function; if omitted
// the job dispatches to /dev/null which is still useful for releasing
// claimed rows and exercising the claim path in tests.
type OutboxDispatchJob struct {
	Outbox  auditapp.OutboxRepository
	Deliver func(ctx context.Context, topic string, payload []byte) error
	Backoff time.Duration
}

func (j OutboxDispatchJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 50
	}
	claimed, err := j.Outbox.Claim(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, rec := range claimed {
		var deliverErr error
		if j.Deliver != nil {
			deliverErr = j.Deliver(ctx, rec.Topic, rec.Payload)
		}
		if deliverErr != nil {
			backoff := j.Backoff
			if backoff <= 0 {
				backoff = 30 * time.Second
			}
			_ = j.Outbox.MarkFailed(ctx, rec.ID, backoff)
			continue
		}
		if err := j.Outbox.MarkDispatched(ctx, rec.ID); err == nil {
			delivered++
		}
	}
	return delivered, nil
}
