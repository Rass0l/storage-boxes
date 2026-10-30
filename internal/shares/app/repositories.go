package app

import (
	"context"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ShareRepository persists share rows.
type ShareRepository interface {
	Put(ctx context.Context, share domain.Share) error
	Get(ctx context.Context, shareID string) (domain.Share, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (domain.Share, error)
	ListByBox(ctx context.Context, boxID string) ([]domain.Share, error)
	ListByCreator(ctx context.Context, userID string) ([]domain.Share, error)
	UpdateStatus(ctx context.Context, shareID, status string, now time.Time) error
	// UpdateSettings mutates the two share knobs that can change after
	// creation: expires_at and max_downloads. Callers pre-validate both;
	// the repo writes them verbatim.
	UpdateSettings(ctx context.Context, shareID string, expiresAt time.Time, maxDownloads int) error
	IncrementDownload(ctx context.Context, shareID string, now time.Time) (int, error)
	ListExpired(ctx context.Context, now time.Time, limit int) ([]domain.Share, error)
	ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Share, error)
	Delete(ctx context.Context, shareID string) error
	MarkPurgeRequested(ctx context.Context, shareID string, now time.Time) error
}

// ShareObjectStore persists metadata about staged objects and owns their
// lifecycle rows.
type ShareObjectStore interface {
	PutObject(ctx context.Context, object domain.ShareObject) error
	GetObject(ctx context.Context, shareID string) (domain.ShareObject, error)
	DeleteObject(ctx context.Context, shareID string) error
}

// ShareAccessRecorder stores share_access_events rows.
type ShareAccessRecorder interface {
	RecordAccess(ctx context.Context, event domain.AccessEvent) error
	ListByShare(ctx context.Context, shareID string, limit int) ([]domain.AccessEvent, error)
	// ListByRecipient returns restricted-delivery rows attributed to a
	// single recipient, newest first. Backs the merged activity
	// timeline on the recipient audit view. Public-share rows (where
	// recipient_id IS NULL) are never returned here.
	ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.AccessEvent, error)
}

// RecipientRepository persists share_recipients rows.
type RecipientRepository interface {
	Put(ctx context.Context, r domain.Recipient) error
	// PutBatch inserts every recipient atomically: either all rows
	// commit or none do. Provisioning uses it so a failure partway
	// through a multi-recipient create/add never strands committed
	// recipient rows (with passcodes the caller never received) or
	// poisons a retry via the UNIQUE(share_id, email_normalized)
	// constraint. An empty slice is a no-op.
	PutBatch(ctx context.Context, recipients []domain.Recipient) error
	Get(ctx context.Context, recipientID string) (domain.Recipient, error)
	GetByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.Recipient, error)
	ListByShare(ctx context.Context, shareID string) ([]domain.Recipient, error)
	// UpdatePasscode rotates the stored salt+hash in place; revoked_at is
	// left untouched so a rotation on a revoked recipient is a no-op from
	// an access-control standpoint.
	UpdatePasscode(ctx context.Context, recipientID string, salt, hash []byte, now time.Time) error
	// ReactivateWithPasscode brings a previously-revoked recipient back to
	// life with a fresh passcode in a SINGLE statement: clears revoked_at,
	// resets failed_attempts, and rewrites salt+hash+passcode_rotated_at
	// atomically. Used by access-request approval of a revoked recipient.
	// Doing it in one UPDATE avoids the ordering hazard of clearing
	// revoked_at and rotating the passcode as two separate writes (a crash
	// between them could leave an active recipient holding a stale passcode).
	// The recipient must still re-verify — no claim is restored.
	ReactivateWithPasscode(ctx context.Context, recipientID string, salt, hash []byte, now time.Time) error
	MarkVerified(ctx context.Context, recipientID string, now time.Time) error
	MarkAttempt(ctx context.Context, recipientID string, succeeded bool, now time.Time) error
	Revoke(ctx context.Context, recipientID string, now time.Time) error
	DeleteByShare(ctx context.Context, shareID string) error
}

// ChallengeRepository appends share_challenges rows. Append-only by DB
// trigger; there is intentionally no Update.
type ChallengeRepository interface {
	Append(ctx context.Context, c domain.Challenge) error
	ListByShare(ctx context.Context, shareID string, limit int) ([]domain.Challenge, error)
	ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.Challenge, error)
	// RecentFailures counts failed passcode attempts for a (share, remoteIP)
	// pair within `within` — used for rate limiting.
	RecentFailures(ctx context.Context, shareID, remoteIP string, since time.Time) (int, error)
}

// ClaimRepository persists share_claims rows.
type ClaimRepository interface {
	Put(ctx context.Context, c domain.Claim) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (domain.Claim, error)
	Get(ctx context.Context, claimID string) (domain.Claim, error)
	ListByShare(ctx context.Context, shareID string) ([]domain.Claim, error)
	ListByRecipient(ctx context.Context, recipientID string) ([]domain.Claim, error)
	// CompleteOTP clears otp_pending + otp_hash once the recipient has
	// presented the correct OTP. Returns an error if the claim doesn't
	// exist or has already been completed/revoked.
	CompleteOTP(ctx context.Context, claimID string, now time.Time) error
	Revoke(ctx context.Context, claimID string, now time.Time) error
	RevokeByRecipient(ctx context.Context, recipientID string, now time.Time) error
	RevokeByShare(ctx context.Context, shareID string, now time.Time) error
	ListExpired(ctx context.Context, now time.Time, limit int) ([]domain.Claim, error)
	// ListActiveWithRevokedRecipient returns un-revoked claims whose
	// recipient row has been revoked. The worker's reconciliation job
	// uses it as a safety net: a revoked recipient's claim is normally
	// cascade-revoked inline, but if that best-effort step was
	// interrupted this surfaces the orphaned-but-live claim so the worker
	// can converge it.
	ListActiveWithRevokedRecipient(ctx context.Context, limit int) ([]domain.Claim, error)
}

// AccessRequestRepository persists share_access_requests rows. Mutable
// (status transitions via Decide), mirroring RecipientRepository; the
// decision history is the append-only audit ledger, not this table.
type AccessRequestRepository interface {
	// Put inserts a new pending request. A UNIQUE(share_id,
	// requester_email_normalized) WHERE status='pending' partial index
	// backstops a race between two simultaneous submits — the loser gets a
	// constraint violation the service treats as a duplicate.
	Put(ctx context.Context, ar domain.AccessRequest) error
	Get(ctx context.Context, id string) (domain.AccessRequest, error)
	// GetPendingByShareEmail returns the single open request for a
	// (share, email) pair, or a not-found error when none is pending.
	GetPendingByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.AccessRequest, error)
	// GetLatestByShareEmail returns the most recently created request for a
	// (share, email) pair regardless of status. Backs the public coarse
	// status endpoint. Not-found when the email never requested.
	GetLatestByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.AccessRequest, error)
	// ListByShare returns requests for a share newest-first. statusFilter ""
	// returns all statuses; a non-empty value filters to that status.
	ListByShare(ctx context.Context, shareID, statusFilter string, limit int) ([]domain.AccessRequest, error)
	// Decide transitions a PENDING request to a terminal status and stamps
	// decision metadata. It MUST be status-guarded (UPDATE ... WHERE
	// id=$1 AND status='pending') and report a no-op when the row is no
	// longer pending, so concurrent owner-deny / worker-expire / worker-
	// supersede races resolve to exactly one terminal transition and the
	// worker stays idempotent. Used by deny + the worker; approval uses
	// ApproveAtomic instead (it also writes recipient policy).
	// recipientID/decidedBy may be empty (system transitions).
	Decide(ctx context.Context, id, status, recipientID, decidedBy, reason string, now time.Time) error
	// ApproveAtomic performs an entire approval as ONE all-or-nothing
	// operation: in a single transaction it status-guards the claim
	// (pending → approved, recipient linked) AND applies the recipient write
	// implied by plan.Mode (insert a new recipient / reactivate a revoked
	// one / none for an already-active recipient). Either the request is
	// approved AND the recipient exists+active+linked, or nothing changes.
	// Returns ErrAccessRequestNotPending (writing nothing) when the request
	// is no longer pending, so a lost race never strands a recipient; any
	// other failure also rolls back, leaving the request pending and the
	// approval safely retryable. The service owns passcode minting + mode
	// selection and emits audit only after this commits.
	ApproveAtomic(ctx context.Context, plan ApprovalPlan) error
	// SupersedeOrphanedApprovals converges approved requests whose recipient
	// state is missing (recipient_id IS NULL) — the "approved request whose
	// recipient state is missing or inconsistent" case the worker owns. It
	// flips them to superseded (reason recipient_missing), returning the
	// rows it changed so the caller can audit each. Guarded on
	// status='approved' AND recipient_id IS NULL, so it's idempotent and
	// only ever touches genuinely-inconsistent rows; it preserves history
	// (no deletes). With atomic approval this state can't arise from a
	// partial write — it's a safety net for restore / migration / a
	// recipient hard-deleted out-of-band.
	SupersedeOrphanedApprovals(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error)
	// ListPendingExpired returns pending requests past their expires_at.
	ListPendingExpired(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error)
	// ListPendingOnDeadShares returns pending requests whose share is no
	// longer deliverable (revoked / expired / purge-requested / purged).
	ListPendingOnDeadShares(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error)
	// ListPendingWithActiveRecipient returns pending requests whose
	// (share, email) already maps to a non-revoked recipient — the request
	// is moot and the worker supersedes it.
	ListPendingWithActiveRecipient(ctx context.Context, limit int) ([]domain.AccessRequest, error)
	// CountRecentByShareIP counts requests created for a (share, remoteIP)
	// pair since `since`. Backs the public submit rate limit so one source
	// can't spam pending rows across many distinct emails.
	CountRecentByShareIP(ctx context.Context, shareID, remoteIP string, since time.Time) (int, error)
	// DeleteByShare removes all requests for a share. Included for interface
	// symmetry; in practice the share_id ON DELETE CASCADE is the mechanism
	// (shares are status-purged, not hard-deleted, on the normal path).
	DeleteByShare(ctx context.Context, shareID string) error
}
