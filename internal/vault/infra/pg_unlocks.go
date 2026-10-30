package infra

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type PGUnlockSessionStore struct{ pool *pgxpool.Pool }

var _ app.UnlockSessionStore = (*PGUnlockSessionStore)(nil)

func NewPGUnlockSessionStore(pool *pgxpool.Pool) *PGUnlockSessionStore {
	return &PGUnlockSessionStore{pool: pool}
}

func (s *PGUnlockSessionStore) Put(ctx context.Context, u domain.UnlockSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO box_unlock_sessions(id, box_id, user_id, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		u.ID, u.BoxID, u.UserID, u.ExpiresAt)
	return err
}

func (s *PGUnlockSessionStore) Get(ctx context.Context, sessionID string) (domain.UnlockSession, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, box_id, user_id, expires_at
		FROM box_unlock_sessions WHERE id = $1`, sessionID)
	var u domain.UnlockSession
	if err := row.Scan(&u.ID, &u.BoxID, &u.UserID, &u.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UnlockSession{}, fmt.Errorf("unlock session not found")
		}
		return domain.UnlockSession{}, err
	}
	return u, nil
}

func (s *PGUnlockSessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM box_unlock_sessions WHERE id = $1`, sessionID)
	return err
}

// Sweep purges expired unlock rows.
func (s *PGUnlockSessionStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM box_unlock_sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
