package infra

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
)

type PGRoleStore struct{ pool *pgxpool.Pool }

var _ app.RoleStore = (*PGRoleStore)(nil)
var _ app.RoleEvaluator = (*PGRoleStore)(nil)

func NewPGRoleStore(pool *pgxpool.Pool) *PGRoleStore { return &PGRoleStore{pool: pool} }

func (r *PGRoleStore) Bind(ctx context.Context, userID, role string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO roles(name, description) VALUES ($1, '') ON CONFLICT DO NOTHING`, role)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO role_bindings(user_id, role_name) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, userID, role)
	return err
}

func (r *PGRoleStore) Unbind(ctx context.Context, userID, role string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM role_bindings WHERE user_id = $1 AND role_name = $2`, userID, role)
	return err
}

func (r *PGRoleStore) RolesFor(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT role_name FROM role_bindings WHERE user_id = $1 ORDER BY role_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (r *PGRoleStore) HasRole(ctx context.Context, userID, role string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM role_bindings WHERE user_id = $1 AND role_name = $2)`,
		userID, role).Scan(&ok)
	return ok, err
}
