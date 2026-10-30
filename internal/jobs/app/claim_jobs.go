package app

import (
	"context"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ClaimExpiryJob sweeps share_claims whose expires_at has passed (or whose
// parent share has been revoked/purged) and stamps revoked_at. The claim
// row stays on disk for audit — just like share_access_events — and the
// terminal `shares.claim_expired` audit record is written once per row so
// operators get a single, queryable marker of the lifecycle transition.
//
// Idempotent: a claim that is already revoked is skipped.
type ClaimExpiryJob struct {
	Claims app.ClaimRepository
	Audit  auditapp.AuditService
}

func (j ClaimExpiryJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := j.Claims.ListExpired(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, c := range rows {
		if c.RevokedAt != nil {
			continue
		}
		if err := j.Claims.Revoke(ctx, c.ID, now); err != nil {
			continue
		}
		if j.Audit != nil {
			_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
				EventType:   auditdomain.EventShareClaimExpired,
				SubjectType: auditdomain.SubjectTypeClaim,
				SubjectID:   c.ID,
				Metadata: map[string]any{
					"share_id":     c.ShareID,
					"recipient_id": c.RecipientID,
					"reason":       "ttl",
				},
				OccurredAt: now,
			})
		}
		done++
	}
	return done, nil
}

// ShareReconciliationJob checks for inconsistencies between the persisted
// share surfaces (shares, claims, recipients) and converges them.
// Concretely, it:
//   - revokes claims whose parent share is non-deliverable (purged,
//     revoked, expired, purge_requested) so a stale cookie never serves
//   - revokes still-active claims whose recipient row has been revoked —
//     the cascade is normally inline, but this is the safety net if that
//     best-effort step was interrupted (delivery is already refused by
//     OpenWithClaim's recipient check; this converges the stored state
//     and audit trail too)
//   - emits a `shares.claim_revoked` per fix-up and a single
//     `shares.reconciled` summary per run
//
// Orphan stage blobs and orphan share_object rows are owned by the
// existing SharePurgeJob and box-deletion cascade; we don't duplicate
// that logic here.
type ShareReconciliationJob struct {
	Shares app.ShareRepository
	Claims app.ClaimRepository
	Audit  auditapp.AuditService
}

func (j ShareReconciliationJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 500
	}
	// Track which claims we've already revoked this run so a claim that
	// is both purge-pending AND recipient-revoked isn't double-counted.
	seen := map[string]struct{}{}
	revoked := 0
	revoke := func(c domain.Claim, reason string) {
		if c.RevokedAt != nil {
			return
		}
		if _, done := seen[c.ID]; done {
			return
		}
		if err := j.Claims.Revoke(ctx, c.ID, now); err != nil {
			return
		}
		seen[c.ID] = struct{}{}
		revoked++
		if j.Audit != nil {
			_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
				EventType:   auditdomain.EventShareClaimRevoked,
				SubjectType: auditdomain.SubjectTypeClaim,
				SubjectID:   c.ID,
				Metadata: map[string]any{
					"share_id":     c.ShareID,
					"recipient_id": c.RecipientID,
					"reason":       reason,
				},
				OccurredAt: now,
			})
		}
	}

	// 1) Claims on purge-pending shares. This is the practical case after
	// a restore: claims may point at shares whose purge hasn't caught up.
	purgeCandidates, err := j.Shares.ListPurgeCandidates(ctx, limit)
	if err != nil {
		return 0, err
	}
	for _, s := range purgeCandidates {
		claims, err := j.Claims.ListByShare(ctx, s.ID)
		if err != nil {
			continue
		}
		for _, c := range claims {
			revoke(c, "reconciled_against_share_state")
		}
	}

	// 2) Live claims whose recipient has been revoked (cascade-miss
	// safety net). Delivery is already refused, but this converges the
	// stored claim state and leaves an explicit audit record.
	orphaned, err := j.Claims.ListActiveWithRevokedRecipient(ctx, limit)
	if err == nil {
		for _, c := range orphaned {
			revoke(c, "recipient_revoked_reconciled")
		}
	}

	if j.Audit != nil {
		_ = j.Audit.Record(ctx, auditdomain.AuditEvent{
			EventType:   auditdomain.EventShareReconciled,
			SubjectType: auditdomain.SubjectTypeShare,
			SubjectID:   "-",
			Metadata: map[string]any{
				"claims_revoked": revoked,
				"shares_scanned": len(purgeCandidates),
			},
			OccurredAt: now,
		})
	}
	return revoked, nil
}
