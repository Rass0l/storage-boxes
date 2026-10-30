package infra

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type PGCredentialStore struct{ pool *pgxpool.Pool }

var _ app.CredentialStore = (*PGCredentialStore)(nil)

func NewPGCredentialStore(pool *pgxpool.Pool) *PGCredentialStore {
	return &PGCredentialStore{pool: pool}
}

func (s *PGCredentialStore) Put(ctx context.Context, c domain.Credential) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_credentials(user_id, password_hash, hash_algorithm, hash_version, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (user_id) DO UPDATE SET
		  password_hash = EXCLUDED.password_hash,
		  hash_algorithm = EXCLUDED.hash_algorithm,
		  hash_version = EXCLUDED.hash_version,
		  updated_at = now()`,
		c.UserID, c.PasswordHash, c.HashAlgorithm, c.HashVersion)
	return err
}

func (s *PGCredentialStore) GetByUserID(ctx context.Context, userID string) (domain.Credential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT user_id, password_hash, hash_algorithm, hash_version
		FROM user_credentials WHERE user_id = $1`, userID)
	var c domain.Credential
	if err := row.Scan(&c.UserID, &c.PasswordHash, &c.HashAlgorithm, &c.HashVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Credential{}, fmt.Errorf("credential not found")
		}
		return domain.Credential{}, err
	}
	return c, nil
}

func (s *PGCredentialStore) GetByEmail(ctx context.Context, email string) (domain.Credential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT c.user_id, c.password_hash, c.hash_algorithm, c.hash_version
		FROM user_credentials c
		JOIN users u ON u.id = c.user_id
		WHERE lower(u.email) = lower($1)`, email)
	var c domain.Credential
	if err := row.Scan(&c.UserID, &c.PasswordHash, &c.HashAlgorithm, &c.HashVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Credential{}, fmt.Errorf("credential not found")
		}
		return domain.Credential{}, err
	}
	return c, nil
}
