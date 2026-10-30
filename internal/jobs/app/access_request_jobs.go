package app

import (
	"context"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// AccessRequestCleanupJob reconciles stale share_access_requests rows against
// the stored model and converges them to a terminal status. Concretely, per
// run it:
//   - expires pending requests past their TTL (status -> expired, reason ttl)
//   - expires pending requests whose share is no longer deliverable
//     (revoked / expired / purge-requested / purged) — they can never be
//     fulfilled (status -> expired, reason share_unavailable)
//   - supersedes pending requests whose (share, email) already maps to an
//     active recipient (the request is moot — status -> superseded)
//   - emits one audit event per transition and a single
//     `shares.access_requests_reconciled` summary
//
// Requests tied to a HARD-deleted share are removed by the share_id
// ON DELETE CASCADE, not here; this job only handles the soft states.
//
// Idempotent: every list query returns only PENDING rows, and the repository's
// status-guarded Decide no-ops on an already-terminal row, so a second run (or
// a concurrent owner decision) never double-counts or double-audits. An
// access request grants nothing on its own, so this is safe to run on the
// regular share tick rather than gated before readiness.
type AccessRequestCleanupJob struct {
	Requests app.AccessRequestRepository
	Audit    auditapp.AuditService
}

func (j AccessRequestCleanupJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if j.Requests == nil {
		return 0, nil
	}
	if limit <= 0 {
		limit = 200
	}
	seen := map[string]struct{}{}
	expired := 0
	superseded := 0

	decide := func(ar domain.AccessRequest, status, reason string) bool {
		if _, done := seen[ar.ID]; done {
			return false
		}
		if err := j.Requests.Decide(ctx, ar.ID, status, "", "", reason, now); err != nil {
			// ErrAccessRequestNotPending (lost race / already terminal) and
			// any transient error both mean "leave it for next run".
			return false
		}
		seen[ar.ID] = struct{}{}
		if j.Audit != nil {
			event := auditdomain.EventShareAccessRequestExpired
			if status == domain.AccessRequestSuperseded {
				event = auditdomain.EventShareAccessRequestSuperseded
			}
			_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
				EventType:   event,
				SubjectType: auditdomain.SubjectTypeAccessRequest,
				SubjectID:   ar.ID,
				Metadata: map[string]any{
					"share_id":        ar.ShareID,
					"requester_email": ar.RequesterEmail,
					"reason":          reason,
				},
				OccurredAt: now,
			})
		}
		return true
	}

	// 1) Pending requests past their TTL.
	if rows, err := j.Requests.ListPendingExpired(ctx, now, limit); err == nil {
		for _, ar := range rows {
			if decide(ar, domain.AccessRequestExpired, domain.AccessReasonExpiredTTL) {
				expired++
			}
		}
	}
	// 2) Pending requests whose share is no longer deliverable.
	if rows, err := j.Requests.ListPendingOnDeadShares(ctx, now, limit); err == nil {
		for _, ar := range rows {
			if decide(ar, domain.AccessRequestExpired, domain.AccessReasonShareUnavailable) {
				expired++
			}
		}
	}
	// 3) Pending requests whose recipient is already active.
	if rows, err := j.Requests.ListPendingWithActiveRecipient(ctx, limit); err == nil {
		for _, ar := range rows {
			if decide(ar, domain.AccessRequestSuperseded, domain.AccessReasonRecipientActive) {
				superseded++
			}
		}
	}
	// 4) APPROVED requests whose recipient state is missing (recipient_id
	// NULL) — the "approved request whose recipient state is missing or
	// inconsistent" case the spec assigns to the worker. Atomic approval
	// prevents this from a partial write; this converges restore / migration
	// / out-of-band-deletion leftovers. SupersedeOrphanedApprovals flips them
	// to superseded atomically and returns the changed rows to audit.
	orphaned := 0
	if rows, err := j.Requests.SupersedeOrphanedApprovals(ctx, now, limit); err == nil {
		for _, ar := range rows {
			orphaned++
			if j.Audit != nil {
				_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
					EventType:   auditdomain.EventShareAccessRequestSuperseded,
					SubjectType: auditdomain.SubjectTypeAccessRequest,
					SubjectID:   ar.ID,
					Metadata: map[string]any{
						"share_id":        ar.ShareID,
						"requester_email": ar.RequesterEmail,
						"reason":          domain.AccessReasonRecipientMissing,
					},
					OccurredAt: now,
				})
			}
		}
	}

	total := expired + superseded + orphaned
	if j.Audit != nil {
		_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
			EventType:   auditdomain.EventShareAccessRequestsReconciled,
			SubjectType: auditdomain.SubjectTypeShare,
			SubjectID:   "-",
			Metadata: map[string]any{
				"expired":            expired,
				"superseded":         superseded,
				"orphaned_approvals": orphaned,
			},
			OccurredAt: now,
		})
	}
	return total, nil
}
