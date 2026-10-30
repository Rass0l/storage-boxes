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

type PGUserStore struct{ pool *pgxpool.Pool }

var _ app.UserStore = (*PGUserStore)(nil)

func NewPGUserStore(pool *pgxpool.Pool) *PGUserStore { return &PGUserStore{pool: pool} }

func (s *PGUserStore) Put(ctx context.Context, user domain.User) error {
	if user.ID == "" || user.Email == "" {
		return fmt.Errorf("user id and email required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users(id, email, display_name, status, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET
		  email = EXCLUDED.email,
		  display_name = EXCLUDED.display_name,
		  status = EXCLUDED.status`,
		user.ID, user.Email, user.DisplayName, defaultStr(user.Status, "active"), user.CreatedAt)
	return err
}

func (s *PGUserStore) GetByID(ctx context.Context, userID string) (domain.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, email, display_name, status, created_at FROM users WHERE id = $1`, userID)
	return scanUser(row)
}

func (s *PGUserStore) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, email, display_name, status, created_at FROM users WHERE lower(email) = lower($1)`, email)
	return scanUser(row)
}

func (s *PGUserStore) List(ctx context.Context) ([]domain.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, display_name, status, created_at FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, fmt.Errorf("user not found")
		}
		return domain.User{}, err
	}
	return u, nil
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
