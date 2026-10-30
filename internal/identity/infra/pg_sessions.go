package infra

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
)

// PGSessionStore persists authentication sessions in Postgres and enforces
// both sliding idle expiry and an absolute hard deadline.
type PGSessionStore struct {
	pool            *pgxpool.Pool
	clock           clock.Clock
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
}

var _ app.SessionService = (*PGSessionStore)(nil)

type PGSessionOptions struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Clock           clock.Clock
}

func NewPGSessionStore(pool *pgxpool.Pool, opts PGSessionOptions) *PGSessionStore {
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 24 * time.Hour
	}
	if opts.AbsoluteTimeout <= 0 {
		opts.AbsoluteTimeout = 7 * 24 * time.Hour
	}
	return &PGSessionStore{pool: pool, clock: opts.Clock,
		idleTimeout: opts.IdleTimeout, absoluteTimeout: opts.AbsoluteTimeout}
}

func pgRandomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *PGSessionStore) Issue(ctx context.Context, user domain.User) (domain.Session, error) {
	token, err := pgRandomToken(32)
	if err != nil {
		return domain.Session{}, fmt.Errorf("session token: %w", err)
	}
	now := s.clock.Now()
	session := domain.Session{
		ID:                token,
		UserID:            user.ID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(s.idleTimeout),
		AbsoluteExpiresAt: now.Add(s.absoluteTimeout),
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO sessions(id, user_id, created_at, expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		session.ID, session.UserID, session.CreatedAt, session.ExpiresAt, session.AbsoluteExpiresAt)
	if err != nil {
		return domain.Session{}, err
	}
	return session, nil
}

func (s *PGSessionStore) Current(ctx context.Context, sessionID string) (domain.Session, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, created_at, expires_at, absolute_expires_at, revoked_at
		FROM sessions WHERE id = $1`, sessionID)
	var sess domain.Session
	var revoked *time.Time
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt,
		&sess.ExpiresAt, &sess.AbsoluteExpiresAt, &revoked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, fmt.Errorf("session not found")
		}
		return domain.Session{}, err
	}
	sess.RevokedAt = revoked

	if sess.RevokedAt != nil {
		return domain.Session{}, fmt.Errorf("session revoked")
	}
	now := s.clock.Now()
	if !sess.AbsoluteExpiresAt.IsZero() && !sess.AbsoluteExpiresAt.After(now) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
		return domain.Session{}, fmt.Errorf("session past absolute lifetime")
	}
	if !sess.ExpiresAt.After(now) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
		return domain.Session{}, fmt.Errorf("session idle-expired")
	}
	next := now.Add(s.idleTimeout)
	if next.After(sess.AbsoluteExpiresAt) {
		next = sess.AbsoluteExpiresAt
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE sessions SET expires_at = $1 WHERE id = $2`, next, sessionID); err != nil {
		return domain.Session{}, err
	}
	sess.ExpiresAt = next
	return sess, nil
}

func (s *PGSessionStore) Revoke(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, sessionID)
	return err
}

// Sweep removes expired and revoked sessions. Intended for the worker or the
// API sweeper goroutine.
func (s *PGSessionStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM sessions
		WHERE revoked_at IS NOT NULL
		   OR expires_at <= $1
		   OR absolute_expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
