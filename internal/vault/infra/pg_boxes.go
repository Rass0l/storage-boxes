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

type PGBoxRepository struct{ pool *pgxpool.Pool }

var _ app.BoxRepository = (*PGBoxRepository)(nil)

func NewPGBoxRepository(pool *pgxpool.Pool) *PGBoxRepository {
	return &PGBoxRepository{pool: pool}
}

func (r *PGBoxRepository) Put(ctx context.Context, box domain.Box) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO boxes(id, owner_user_id, name, size_bytes, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
		  name = EXCLUDED.name,
		  size_bytes = EXCLUDED.size_bytes,
		  status = EXCLUDED.status`,
		box.ID, box.OwnerUserID, box.Name, box.SizeBytes, box.Status, box.CreatedAt)
	return err
}

func scanBox(row interface {
	Scan(dest ...any) error
}) (domain.Box, error) {
	var b domain.Box
	if err := row.Scan(&b.ID, &b.OwnerUserID, &b.Name, &b.SizeBytes, &b.Status, &b.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Box{}, fmt.Errorf("box not found")
		}
		return domain.Box{}, err
	}
	return b, nil
}

func (r *PGBoxRepository) Get(ctx context.Context, boxID string) (domain.Box, error) {
	return scanBox(r.pool.QueryRow(ctx, `
		SELECT id, owner_user_id, name, size_bytes, status, created_at FROM boxes WHERE id = $1`, boxID))
}

// ListByOwner returns the caller's live boxes. Rows in status='deleting'
// are hidden so the listing matches what the user can still act on —
// the same filter the memory repo applies. Operators who need to see
// in-flight deletions should query via ListPurgeCandidates.
func (r *PGBoxRepository) ListByOwner(ctx context.Context, ownerUserID string) ([]domain.Box, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, owner_user_id, name, size_bytes, status, created_at
		FROM boxes
		WHERE owner_user_id = $1 AND status <> 'deleting'
		ORDER BY created_at ASC`, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Box{}
	for rows.Next() {
		b, err := scanBox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (r *PGBoxRepository) Delete(ctx context.Context, boxID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, boxID)
	return err
}

// SoftDelete flips status to 'deleting' and stamps deleted_at +
// purge_requested_at. Uses the columns added by migration 013.
// Idempotent: a second call leaves the original stamps in place so
// observability stays stable.
func (r *PGBoxRepository) SoftDelete(ctx context.Context, boxID string, now time.Time) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE boxes
		   SET status = 'deleting',
		       deleted_at         = COALESCE(deleted_at, $1),
		       purge_requested_at = COALESCE(purge_requested_at, $1)
		 WHERE id = $2`, now, boxID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("box not found")
	}
	return nil
}

// ListPurgeCandidates returns soft-deleted boxes pending finalize,
// oldest request first so slow-converging cleanups don't get starved.
func (r *PGBoxRepository) ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Box, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, owner_user_id, name, size_bytes, status, created_at
		FROM boxes
		WHERE purge_requested_at IS NOT NULL
		ORDER BY purge_requested_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Box{}
	for rows.Next() {
		b, err := scanBox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// FinalizeDelete is the hard DELETE — FK CASCADE drops whatever child
// rows survive. Only safe to call after cross-subsystem cleanup (shares,
// blobs) has converged. The worker's BoxPurgeJob is the sole production
// caller.
func (r *PGBoxRepository) FinalizeDelete(ctx context.Context, boxID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, boxID)
	return err
}

// PutBoxAtomic inserts a box row and its crypto material in a single
// transaction so a crash between the two never leaves a half-created box.
func (r *PGBoxRepository) PutBoxAtomic(ctx context.Context, box domain.Box, m domain.BoxCryptoMaterial) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO boxes(id, owner_user_id, name, size_bytes, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		box.ID, box.OwnerUserID, box.Name, box.SizeBytes, box.Status, box.CreatedAt); err != nil {
		return err
	}
	kdf, _ := jsonMarshal(kdfParams{
		Salt: base64Std(m.KDFSalt), Time: m.KDFTime, Memory: m.KDFMemory, Threads: m.KDFThreads,
	})
	cp, _ := jsonMarshal(cipherParams{Nonce: base64Std(m.Nonce)})
	if _, err := tx.Exec(ctx, `
		INSERT INTO box_crypto_material(
			box_id, crypto_version, kdf_algorithm, kdf_params,
			cipher_algorithm, cipher_params,
			key_wrapping_algorithm, wrapped_box_master_key)
		VALUES ($1, 1, $2, $3, $4, $5, 'aead', $6)`,
		m.BoxID, m.KDFAlgorithm, kdf, m.CipherAlgo, cp, m.WrappedBMK); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
