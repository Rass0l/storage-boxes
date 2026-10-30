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

// PGRecipientRepository persists share_recipients rows.
type PGRecipientRepository struct{ pool *pgxpool.Pool }

var _ app.RecipientRepository = (*PGRecipientRepository)(nil)

func NewPGRecipientRepository(pool *pgxpool.Pool) *PGRecipientRepository {
	return &PGRecipientRepository{pool: pool}
}

const recipientSelect = `
SELECT id, share_id, email, email_normalized, passcode_hash, passcode_salt,
       passcode_rotated_at, verified_at, revoked_at, failed_attempts, last_attempt_at, created_at
FROM share_recipients`

func (r *PGRecipientRepository) Put(ctx context.Context, rec domain.Recipient) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO share_recipients(id, share_id, email, email_normalized, passcode_hash, passcode_salt, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		rec.ID, rec.ShareID, rec.Email, rec.EmailNormalized, rec.PasscodeHash, rec.PasscodeSalt, rec.CreatedAt)
	return err
}

// PutBatch inserts all recipients in a single transaction so a failure on
// any row (including a UNIQUE(share_id, email_normalized) violation) rolls
// back the whole batch — no half-provisioned recipient set survives.
// Mirrors PGBoxRepository.PutBoxAtomic.
func (r *PGRecipientRepository) PutBatch(ctx context.Context, recipients []domain.Recipient) error {
	if len(recipients) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, rec := range recipients {
		if _, err := tx.Exec(ctx, `
			INSERT INTO share_recipients(id, share_id, email, email_normalized, passcode_hash, passcode_salt, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			rec.ID, rec.ShareID, rec.Email, rec.EmailNormalized, rec.PasscodeHash, rec.PasscodeSalt, rec.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PGRecipientRepository) Get(ctx context.Context, id string) (domain.Recipient, error) {
	return r.scan(r.pool.QueryRow(ctx, recipientSelect+` WHERE id = $1`, id))
}

func (r *PGRecipientRepository) GetByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.Recipient, error) {
	return r.scan(r.pool.QueryRow(ctx, recipientSelect+` WHERE share_id = $1 AND email_normalized = $2`, shareID, emailNormalized))
}

func (r *PGRecipientRepository) ListByShare(ctx context.Context, shareID string) ([]domain.Recipient, error) {
	rows, err := r.pool.Query(ctx, recipientSelect+` WHERE share_id = $1 ORDER BY created_at`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Recipient{}
	for rows.Next() {
		rec, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *PGRecipientRepository) UpdatePasscode(ctx context.Context, id string, salt, hash []byte, now time.Time) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE share_recipients SET passcode_hash=$1, passcode_salt=$2, passcode_rotated_at=$3, failed_attempts=0
		WHERE id=$4`, hash, salt, now, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("recipient not found")
	}
	return nil
}

// ReactivateWithPasscode clears revoked_at, resets failed_attempts, and
// rewrites the passcode salt+hash in one statement so an access-request
// approval of a previously-revoked recipient can never leave a window where
// the recipient is active under a stale passcode.
func (r *PGRecipientRepository) ReactivateWithPasscode(ctx context.Context, id string, salt, hash []byte, now time.Time) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE share_recipients
		SET revoked_at = NULL, failed_attempts = 0,
		    passcode_hash = $1, passcode_salt = $2, passcode_rotated_at = $3
		WHERE id = $4`, hash, salt, now, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("recipient not found")
	}
	return nil
}

func (r *PGRecipientRepository) MarkVerified(ctx context.Context, id string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE share_recipients SET verified_at = COALESCE(verified_at, $1) WHERE id = $2`, now, id)
	return err
}

func (r *PGRecipientRepository) MarkAttempt(ctx context.Context, id string, succeeded bool, now time.Time) error {
	if succeeded {
		_, err := r.pool.Exec(ctx, `UPDATE share_recipients SET failed_attempts = 0, last_attempt_at = $1 WHERE id = $2`, now, id)
		return err
	}
	_, err := r.pool.Exec(ctx, `UPDATE share_recipients SET failed_attempts = failed_attempts + 1, last_attempt_at = $1 WHERE id = $2`, now, id)
	return err
}

func (r *PGRecipientRepository) Revoke(ctx context.Context, id string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE share_recipients SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`, now, id)
	return err
}

func (r *PGRecipientRepository) DeleteByShare(ctx context.Context, shareID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM share_recipients WHERE share_id = $1`, shareID)
	return err
}

func (r *PGRecipientRepository) scan(row interface{ Scan(...any) error }) (domain.Recipient, error) {
	var rec domain.Recipient
	var rotated, verified, revoked, last *time.Time
	if err := row.Scan(&rec.ID, &rec.ShareID, &rec.Email, &rec.EmailNormalized,
		&rec.PasscodeHash, &rec.PasscodeSalt, &rotated, &verified, &revoked,
		&rec.FailedAttempts, &last, &rec.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Recipient{}, fmt.Errorf("recipient not found")
		}
		return domain.Recipient{}, err
	}
	rec.PasscodeRotatedAt = rotated
	rec.VerifiedAt = verified
	rec.RevokedAt = revoked
	rec.LastAttemptAt = last
	return rec, nil
}

// PGChallengeRepository appends share_challenges rows.
type PGChallengeRepository struct{ pool *pgxpool.Pool }

var _ app.ChallengeRepository = (*PGChallengeRepository)(nil)

func NewPGChallengeRepository(pool *pgxpool.Pool) *PGChallengeRepository {
	return &PGChallengeRepository{pool: pool}
}

func (r *PGChallengeRepository) Append(ctx context.Context, c domain.Challenge) error {
	meta, _ := json.Marshal(c.Metadata)
	var ip, ua, rec, cc, reason any
	if c.RemoteIP != "" {
		ip = c.RemoteIP
	}
	if c.UserAgent != "" {
		ua = c.UserAgent
	}
	if c.RecipientID != "" {
		rec = c.RecipientID
	}
	if c.CountryCode != "" {
		cc = c.CountryCode
	}
	if c.Reason != "" {
		reason = c.Reason
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO share_challenges(id, share_id, recipient_id, kind, succeeded, reason, remote_ip, user_agent, attempted_at, risk_score, country_code, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.ID, c.ShareID, rec, c.Kind, c.Succeeded, reason, ip, ua, c.AttemptedAt, c.RiskScore, cc, meta)
	return err
}

func (r *PGChallengeRepository) ListByShare(ctx context.Context, shareID string, limit int) ([]domain.Challenge, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, `WHERE share_id = $1 ORDER BY attempted_at DESC LIMIT $2`, shareID, limit)
}

func (r *PGChallengeRepository) ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.Challenge, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, `WHERE recipient_id = $1 ORDER BY attempted_at DESC LIMIT $2`, recipientID, limit)
}

func (r *PGChallengeRepository) RecentFailures(ctx context.Context, shareID, remoteIP string, since time.Time) (int, error) {
	var n int
	var ip any
	if remoteIP != "" {
		ip = remoteIP
	}
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM share_challenges
		WHERE share_id = $1 AND succeeded = false AND attempted_at >= $2
		  AND ($3::inet IS NULL OR remote_ip = $3::inet)`, shareID, since, ip).Scan(&n)
	return n, err
}

func (r *PGChallengeRepository) list(ctx context.Context, where string, args ...any) ([]domain.Challenge, error) {
	q := `SELECT id, share_id, COALESCE(recipient_id,''), kind, succeeded, COALESCE(reason,''),
	             COALESCE(host(remote_ip),''), COALESCE(user_agent,''), attempted_at,
	             risk_score, COALESCE(country_code,''), metadata
	      FROM share_challenges ` + where
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Challenge{}
	for rows.Next() {
		var c domain.Challenge
		var meta []byte
		if err := rows.Scan(&c.ID, &c.ShareID, &c.RecipientID, &c.Kind, &c.Succeeded, &c.Reason,
			&c.RemoteIP, &c.UserAgent, &c.AttemptedAt, &c.RiskScore, &c.CountryCode, &meta); err != nil {
			return nil, err
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &c.Metadata)
		}
		if c.Metadata == nil {
			c.Metadata = map[string]any{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PGClaimRepository persists share_claims rows.
type PGClaimRepository struct{ pool *pgxpool.Pool }

var _ app.ClaimRepository = (*PGClaimRepository)(nil)

func NewPGClaimRepository(pool *pgxpool.Pool) *PGClaimRepository {
	return &PGClaimRepository{pool: pool}
}

const claimSelect = `
SELECT id, share_id, recipient_id, token_hash, issued_at, expires_at, revoked_at,
       otp_pending, otp_hash, otp_expires_at, COALESCE(host(remote_ip),''), COALESCE(user_agent,'')
FROM share_claims`

func (r *PGClaimRepository) Put(ctx context.Context, c domain.Claim) error {
	var ip, ua any
	if c.RemoteIP != "" {
		ip = c.RemoteIP
	}
	if c.UserAgent != "" {
		ua = c.UserAgent
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO share_claims(id, share_id, recipient_id, token_hash, issued_at, expires_at, otp_pending, otp_hash, otp_expires_at, remote_ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		c.ID, c.ShareID, c.RecipientID, c.TokenHash, c.IssuedAt, c.ExpiresAt, c.OTPPending, c.OTPHash, c.OTPExpiresAt, ip, ua)
	return err
}

func (r *PGClaimRepository) GetByTokenHash(ctx context.Context, h []byte) (domain.Claim, error) {
	return r.scan(r.pool.QueryRow(ctx, claimSelect+` WHERE token_hash = $1`, h))
}

func (r *PGClaimRepository) Get(ctx context.Context, id string) (domain.Claim, error) {
	return r.scan(r.pool.QueryRow(ctx, claimSelect+` WHERE id = $1`, id))
}

func (r *PGClaimRepository) ListByShare(ctx context.Context, shareID string) ([]domain.Claim, error) {
	return r.list(ctx, claimSelect+` WHERE share_id = $1 ORDER BY issued_at DESC`, shareID)
}

func (r *PGClaimRepository) ListByRecipient(ctx context.Context, recipientID string) ([]domain.Claim, error) {
	return r.list(ctx, claimSelect+` WHERE recipient_id = $1 ORDER BY issued_at DESC`, recipientID)
}

func (r *PGClaimRepository) CompleteOTP(ctx context.Context, id string, now time.Time) error {
	_ = now
	ct, err := r.pool.Exec(ctx, `
		UPDATE share_claims SET otp_pending = false, otp_hash = NULL, otp_expires_at = NULL
		WHERE id = $1 AND otp_pending = true AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("claim not pending")
	}
	return nil
}

func (r *PGClaimRepository) Revoke(ctx context.Context, id string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE share_claims SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`, now, id)
	return err
}

func (r *PGClaimRepository) RevokeByRecipient(ctx context.Context, recipientID string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE share_claims SET revoked_at = COALESCE(revoked_at, $1) WHERE recipient_id = $2`, now, recipientID)
	return err
}

func (r *PGClaimRepository) RevokeByShare(ctx context.Context, shareID string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE share_claims SET revoked_at = COALESCE(revoked_at, $1) WHERE share_id = $2`, now, shareID)
	return err
}

func (r *PGClaimRepository) ListExpired(ctx context.Context, now time.Time, limit int) ([]domain.Claim, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, claimSelect+` WHERE revoked_at IS NULL AND expires_at <= $1 LIMIT $2`, now, limit)
}

func (r *PGClaimRepository) ListActiveWithRevokedRecipient(ctx context.Context, limit int) ([]domain.Claim, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, `
		SELECT c.id, c.share_id, c.recipient_id, c.token_hash, c.issued_at, c.expires_at, c.revoked_at,
		       c.otp_pending, c.otp_hash, c.otp_expires_at, COALESCE(host(c.remote_ip),''), COALESCE(c.user_agent,'')
		FROM share_claims c
		JOIN share_recipients r ON r.id = c.recipient_id
		WHERE c.revoked_at IS NULL AND r.revoked_at IS NOT NULL
		LIMIT $1`, limit)
}

func (r *PGClaimRepository) list(ctx context.Context, sql string, args ...any) ([]domain.Claim, error) {
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Claim{}
	for rows.Next() {
		c, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *PGClaimRepository) scan(row interface{ Scan(...any) error }) (domain.Claim, error) {
	var c domain.Claim
	var revoked, otpExp *time.Time
	var otpHash []byte
	if err := row.Scan(&c.ID, &c.ShareID, &c.RecipientID, &c.TokenHash, &c.IssuedAt,
		&c.ExpiresAt, &revoked, &c.OTPPending, &otpHash, &otpExp, &c.RemoteIP, &c.UserAgent); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Claim{}, fmt.Errorf("claim not found")
		}
		return domain.Claim{}, err
	}
	c.RevokedAt = revoked
	c.OTPHash = otpHash
	c.OTPExpiresAt = otpExp
	return c, nil
}
