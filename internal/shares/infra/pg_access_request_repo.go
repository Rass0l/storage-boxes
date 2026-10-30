package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// PGAccessRequestRepository persists share_access_requests rows.
type PGAccessRequestRepository struct{ pool *pgxpool.Pool }

var _ app.AccessRequestRepository = (*PGAccessRequestRepository)(nil)

func NewPGAccessRequestRepository(pool *pgxpool.Pool) *PGAccessRequestRepository {
	return &PGAccessRequestRepository{pool: pool}
}

const accessRequestSelect = `
SELECT id, share_id, requester_email, requester_email_normalized, requester_domain,
       COALESCE(message,''), status, COALESCE(recipient_id,''), COALESCE(decided_by,''),
       decided_at, COALESCE(decision_reason,''), expires_at,
       COALESCE(host(remote_ip),''), COALESCE(user_agent,''), COALESCE(referer,''),
       risk_score, COALESCE(country_code,''), created_at, metadata
FROM share_access_requests`

func (r *PGAccessRequestRepository) Put(ctx context.Context, ar domain.AccessRequest) error {
	meta, _ := json.Marshal(ar.Metadata)
	var msg, recipient, decidedBy, reason, ip, ua, referer, cc any
	if ar.Message != "" {
		msg = ar.Message
	}
	if ar.RecipientID != "" {
		recipient = ar.RecipientID
	}
	if ar.DecidedBy != "" {
		decidedBy = ar.DecidedBy
	}
	if ar.DecisionReason != "" {
		reason = ar.DecisionReason
	}
	if ar.RemoteIP != "" {
		ip = ar.RemoteIP
	}
	if ar.UserAgent != "" {
		ua = ar.UserAgent
	}
	if ar.Referer != "" {
		referer = ar.Referer
	}
	if ar.CountryCode != "" {
		cc = ar.CountryCode
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO share_access_requests(id, share_id, requester_email, requester_email_normalized,
			requester_domain, message, status, recipient_id, decided_by, decided_at, decision_reason,
			expires_at, remote_ip, user_agent, referer, risk_score, country_code, created_at, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		ar.ID, ar.ShareID, ar.RequesterEmail, ar.RequesterEmailNormalized, ar.RequesterDomain,
		msg, ar.Status, recipient, decidedBy, ar.DecidedAt, reason, ar.ExpiresAt,
		ip, ua, referer, ar.RiskScore, cc, ar.CreatedAt, meta)
	return err
}

func (r *PGAccessRequestRepository) Get(ctx context.Context, id string) (domain.AccessRequest, error) {
	return r.scan(r.pool.QueryRow(ctx, accessRequestSelect+` WHERE id = $1`, id))
}

func (r *PGAccessRequestRepository) GetPendingByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.AccessRequest, error) {
	return r.scan(r.pool.QueryRow(ctx, accessRequestSelect+
		` WHERE share_id = $1 AND requester_email_normalized = $2 AND status = 'pending'`, shareID, emailNormalized))
}

func (r *PGAccessRequestRepository) GetLatestByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.AccessRequest, error) {
	return r.scan(r.pool.QueryRow(ctx, accessRequestSelect+
		` WHERE share_id = $1 AND requester_email_normalized = $2 ORDER BY created_at DESC LIMIT 1`, shareID, emailNormalized))
}

func (r *PGAccessRequestRepository) ListByShare(ctx context.Context, shareID, statusFilter string, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if statusFilter != "" {
		return r.list(ctx, accessRequestSelect+
			` WHERE share_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3`, shareID, statusFilter, limit)
	}
	return r.list(ctx, accessRequestSelect+
		` WHERE share_id = $1 ORDER BY created_at DESC LIMIT $2`, shareID, limit)
}

// Decide is a status-guarded transition: it only mutates a row that is still
// pending, so concurrent owner-approve / worker-supersede attempts resolve to
// exactly one winner and the worker stays idempotent across runs. A no-op
// (RowsAffected==0) returns a sentinel the caller treats as "already decided".
func (r *PGAccessRequestRepository) Decide(ctx context.Context, id, status, recipientID, decidedBy, reason string, now time.Time) error {
	var recipient, by, rsn any
	if recipientID != "" {
		recipient = recipientID
	}
	if decidedBy != "" {
		by = decidedBy
	}
	if reason != "" {
		rsn = reason
	}
	ct, err := r.pool.Exec(ctx, `
		UPDATE share_access_requests
		SET status = $2, recipient_id = COALESCE($3::text, recipient_id),
		    decided_by = $4::text, decided_at = $5, decision_reason = $6::text
		WHERE id = $1 AND status = 'pending'`,
		id, status, recipient, by, now, rsn)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return app.ErrAccessRequestNotPending
	}
	return nil
}

// ApproveAtomic claims the request and writes the recipient in ONE
// transaction. Mirrors PGBoxRepository.PutBoxAtomic: a crash or error between
// the two writes can't leave a half-applied approval. The status-guarded claim
// is the commit gate — if the request is no longer pending the whole tx rolls
// back and ErrAccessRequestNotPending is returned having written nothing.
func (r *PGAccessRequestRepository) ApproveAtomic(ctx context.Context, plan app.ApprovalPlan) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 1. Recipient write implied by the mode, FIRST — the request's
	// recipient_id FK is immediate, so for a New recipient the row must exist
	// before the claim references it. Order within the transaction doesn't
	// affect atomicity (a failed claim below rolls this back); it only
	// satisfies the FK.
	switch plan.Mode {
	case app.ApprovalModeNew:
		if _, err := tx.Exec(ctx, `
			INSERT INTO share_recipients(id, share_id, email, email_normalized, passcode_hash, passcode_salt, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			plan.Recipient.ID, plan.Recipient.ShareID, plan.Recipient.Email, plan.Recipient.EmailNormalized,
			plan.Recipient.PasscodeHash, plan.Recipient.PasscodeSalt, plan.Recipient.CreatedAt); err != nil {
			return err // e.g. a concurrent provision; rollback leaves the request pending + retryable
		}
	case app.ApprovalModeReactivate:
		rc, err := tx.Exec(ctx, `
			UPDATE share_recipients
			SET revoked_at = NULL, failed_attempts = 0, passcode_hash = $2, passcode_salt = $3, passcode_rotated_at = $4
			WHERE id = $1`,
			plan.Recipient.ID, plan.Recipient.PasscodeHash, plan.Recipient.PasscodeSalt, plan.Now)
		if err != nil {
			return err
		}
		if rc.RowsAffected() == 0 {
			return fmt.Errorf("recipient not found")
		}
	case app.ApprovalModeLink:
		// Recipient already active; nothing to write.
	default:
		return fmt.Errorf("unknown approval mode %q", plan.Mode)
	}

	// 2. Status-guarded claim — the commit gate. recipient_id now references a
	// row that exists (written above). If the request is no longer pending the
	// whole transaction (including the recipient write) rolls back, so a lost
	// race persists nothing.
	ct, err := tx.Exec(ctx, `
		UPDATE share_access_requests
		SET status = 'approved', recipient_id = $2, decided_by = $3, decided_at = $4, decision_reason = $5
		WHERE id = $1 AND status = 'pending'`,
		plan.RequestID, plan.Recipient.ID, plan.DecidedBy, plan.Now, plan.Reason)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return app.ErrAccessRequestNotPending
	}
	return tx.Commit(ctx)
}

// SupersedeOrphanedApprovals flips approved requests whose recipient state is
// missing (recipient_id IS NULL) to superseded, returning the changed rows so
// the worker can audit each. UPDATE … RETURNING is atomic and idempotent: once
// a row is superseded it no longer matches the guard.
func (r *PGAccessRequestRepository) SupersedeOrphanedApprovals(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		WITH victims AS (
		  SELECT id FROM share_access_requests
		  WHERE status = 'approved' AND recipient_id IS NULL
		  LIMIT $2
		)
		UPDATE share_access_requests ar
		SET status = 'superseded', decision_reason = $3, decided_at = COALESCE(ar.decided_at, $1)
		FROM victims WHERE ar.id = victims.id
		RETURNING ar.id, ar.share_id, ar.requester_email, ar.requester_email_normalized, ar.requester_domain,
		          COALESCE(ar.message,''), ar.status, COALESCE(ar.recipient_id,''), COALESCE(ar.decided_by,''),
		          ar.decided_at, COALESCE(ar.decision_reason,''), ar.expires_at,
		          COALESCE(host(ar.remote_ip),''), COALESCE(ar.user_agent,''), COALESCE(ar.referer,''),
		          ar.risk_score, COALESCE(ar.country_code,''), ar.created_at, ar.metadata`,
		now, limit, domain.AccessReasonRecipientMissing)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AccessRequest{}
	for rows.Next() {
		ar, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ar)
	}
	return out, rows.Err()
}

func (r *PGAccessRequestRepository) ListPendingExpired(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	return r.list(ctx, accessRequestSelect+
		` WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= $1 LIMIT $2`, now, limit)
}

func (r *PGAccessRequestRepository) ListPendingOnDeadShares(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	// A share is dead for request purposes when it is non-deliverable:
	// purge_requested stamped, status != active, or past expiry.
	return r.list(ctx, `
		SELECT ar.id, ar.share_id, ar.requester_email, ar.requester_email_normalized, ar.requester_domain,
		       COALESCE(ar.message,''), ar.status, COALESCE(ar.recipient_id,''), COALESCE(ar.decided_by,''),
		       ar.decided_at, COALESCE(ar.decision_reason,''), ar.expires_at,
		       COALESCE(host(ar.remote_ip),''), COALESCE(ar.user_agent,''), COALESCE(ar.referer,''),
		       ar.risk_score, COALESCE(ar.country_code,''), ar.created_at, ar.metadata
		FROM share_access_requests ar
		JOIN shares s ON s.id = ar.share_id
		WHERE ar.status = 'pending'
		  AND (s.purge_requested_at IS NOT NULL OR s.status <> 'active' OR s.expires_at <= $1)
		LIMIT $2`, now, limit)
}

func (r *PGAccessRequestRepository) ListPendingWithActiveRecipient(ctx context.Context, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	return r.list(ctx, `
		SELECT ar.id, ar.share_id, ar.requester_email, ar.requester_email_normalized, ar.requester_domain,
		       COALESCE(ar.message,''), ar.status, COALESCE(ar.recipient_id,''), COALESCE(ar.decided_by,''),
		       ar.decided_at, COALESCE(ar.decision_reason,''), ar.expires_at,
		       COALESCE(host(ar.remote_ip),''), COALESCE(ar.user_agent,''), COALESCE(ar.referer,''),
		       ar.risk_score, COALESCE(ar.country_code,''), ar.created_at, ar.metadata
		FROM share_access_requests ar
		JOIN share_recipients sr
		  ON sr.share_id = ar.share_id AND sr.email_normalized = ar.requester_email_normalized
		WHERE ar.status = 'pending' AND sr.revoked_at IS NULL
		LIMIT $1`, limit)
}

func (r *PGAccessRequestRepository) CountRecentByShareIP(ctx context.Context, shareID, remoteIP string, since time.Time) (int, error) {
	var n int
	var ip any
	if remoteIP != "" {
		ip = remoteIP
	}
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM share_access_requests
		WHERE share_id = $1 AND created_at >= $2
		  AND ($3::inet IS NULL OR remote_ip = $3::inet)`, shareID, since, ip).Scan(&n)
	return n, err
}

func (r *PGAccessRequestRepository) DeleteByShare(ctx context.Context, shareID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM share_access_requests WHERE share_id = $1`, shareID)
	return err
}

func (r *PGAccessRequestRepository) list(ctx context.Context, sql string, args ...any) ([]domain.AccessRequest, error) {
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AccessRequest{}
	for rows.Next() {
		ar, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ar)
	}
	return out, rows.Err()
}

func (r *PGAccessRequestRepository) scan(row interface{ Scan(...any) error }) (domain.AccessRequest, error) {
	var ar domain.AccessRequest
	var decidedAt, expiresAt *time.Time
	var meta []byte
	if err := row.Scan(&ar.ID, &ar.ShareID, &ar.RequesterEmail, &ar.RequesterEmailNormalized,
		&ar.RequesterDomain, &ar.Message, &ar.Status, &ar.RecipientID, &ar.DecidedBy,
		&decidedAt, &ar.DecisionReason, &expiresAt, &ar.RemoteIP, &ar.UserAgent, &ar.Referer,
		&ar.RiskScore, &ar.CountryCode, &ar.CreatedAt, &meta); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessRequest{}, fmt.Errorf("access request not found")
		}
		return domain.AccessRequest{}, err
	}
	ar.DecidedAt = decidedAt
	ar.ExpiresAt = expiresAt
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &ar.Metadata)
	}
	if ar.Metadata == nil {
		ar.Metadata = map[string]any{}
	}
	return ar, nil
}
