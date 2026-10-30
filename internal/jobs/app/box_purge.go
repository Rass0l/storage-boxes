package app

import (
	"context"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	sharesapp "github.com/Rass0l/storage-boxes/internal/shares/app"
	sharesdomain "github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// BoxFinalizer is the narrow vault capability BoxPurgeJob needs. Kept as
// an interface so the job is exercisable without standing up the full
// vault service in tests.
type BoxFinalizer interface {
	// ListPurgeCandidateBoxes returns boxes currently in the 'deleting'
	// state with purge_requested_at set, oldest first.
	ListPurgeCandidateBoxes(ctx context.Context, limit int) ([]BoxRef, error)
	// FinalizeBox hard-deletes the box and wipes its blob directory.
	// Callers must only invoke this once the box has no unpurged shares.
	FinalizeBox(ctx context.Context, boxID string) error
}

// BoxRef is the minimal shape BoxPurgeJob needs. The vault service
// fills this in from its own domain.Box.
type BoxRef struct {
	ID      string
	OwnerID string
}

// BoxPurgeJob finalizes soft-deleted boxes. On each run it:
//  1. Lists soft-deleted boxes.
//  2. For each box: drives SharePurgeJob to convergence for that box's
//     shares, then (only when every share has reached `purged`) calls
//     FinalizeBox.
//
// Idempotent. Safe across worker restarts. A single slow converging
// share does not block other boxes — the job continues the loop and
// retries the sluggish box on the next tick.
type BoxPurgeJob struct {
	Boxes  BoxFinalizer
	Shares sharesapp.ShareRepository
	Purger SharePurgeJob
	Audit  auditapp.AuditService
}

// Run processes up to `limit` soft-deleted boxes. Returns the number of
// boxes that were finalized this tick.
func (j BoxPurgeJob) Run(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 50
	}
	boxes, err := j.Boxes.ListPurgeCandidateBoxes(ctx, limit)
	if err != nil {
		return 0, err
	}
	finalized := 0
	for _, box := range boxes {
		// Push the share purger forward on THIS box's shares. The
		// SharePurgeJob itself takes a global claim, so we iterate the
		// candidates directly here for a tight per-box convergence
		// check.
		shares, err := j.Shares.ListByBox(ctx, box.ID)
		if err != nil {
			continue
		}
		allPurged := true
		for _, sh := range shares {
			if sh.Status == sharesdomain.StatusPurged {
				continue
			}
			// Drive this share toward purged via the share purger's
			// single-share path. Best-effort: if the stage delete
			// fails we'll retry next tick.
			j.Purger.runOne(ctx, sh, now)
			// Re-read so we see the updated status before deciding
			// whether the box is convergeable this tick.
			got, err := j.Shares.Get(ctx, sh.ID)
			if err != nil || got.Status != sharesdomain.StatusPurged {
				allPurged = false
			}
		}
		if !allPurged {
			continue
		}
		if err := j.Boxes.FinalizeBox(ctx, box.ID); err != nil {
			continue
		}
		// NOTE: `vault.box_deleted` is emitted by the vault service's
		// FinalizeBox itself, AFTER blob wipe + metadata DELETE both
		// succeed. We do NOT re-emit here — doing so would double-log
		// every finalized box (once from vault, once from the job)
		// and inflate `/api/v1/audit/events` counts.
		finalized++
	}
	return finalized, nil
}
