package infra

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type PGFileCatalog struct{ pool *pgxpool.Pool }

var _ app.FileCatalogRepository = (*PGFileCatalog)(nil)

func NewPGFileCatalog(pool *pgxpool.Pool) *PGFileCatalog { return &PGFileCatalog{pool: pool} }

const folderContentType = "inode/directory"

func kindFor(contentType string) string {
	if contentType == folderContentType {
		return "folder"
	}
	return "file"
}

func (r *PGFileCatalog) PutFileEntry(ctx context.Context, e domain.FileEntry) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO file_entries(id, box_id, parent_id, logical_path, name, content_type, size_bytes, kind, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (id) DO UPDATE SET
		  parent_id = EXCLUDED.parent_id,
		  logical_path = EXCLUDED.logical_path,
		  name = EXCLUDED.name,
		  content_type = EXCLUDED.content_type,
		  size_bytes = EXCLUDED.size_bytes,
		  kind = EXCLUDED.kind,
		  updated_at = now()`,
		e.ID, e.BoxID, e.ParentID, e.LogicalPath, e.Name,
		defaultStr(e.ContentType, "application/octet-stream"),
		e.SizeBytes, kindFor(e.ContentType), e.CreatedAt)
	return err
}

// RenameSubtree moves a file or folder and (for folders) every descendant in
// a single transaction. Each updated row has its logical_path rewritten and,
// for the moved root, its parent_id too.
func (r *PGFileCatalog) RenameSubtree(
	ctx context.Context, boxID, fromPath, toPath string, newParentID *string,
) (domain.FileEntry, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.FileEntry{}, err
	}
	defer tx.Rollback(ctx)

	// Lock the moving subtree. Using FOR UPDATE prevents a concurrent
	// inserter from slipping a conflicting entry in under us.
	fromPrefix := trimTrailSlash(fromPath) + "/"
	if _, err := tx.Exec(ctx, `
		SELECT id FROM file_entries
		WHERE box_id = $1 AND (logical_path = $2 OR logical_path LIKE $3)
		FOR UPDATE`, boxID, fromPath, fromPrefix+"%"); err != nil {
		return domain.FileEntry{}, err
	}

	// Ensure no row already exists at the target path or under it.
	var conflict int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM file_entries
		WHERE box_id = $1 AND (logical_path = $2 OR logical_path LIKE $3)`,
		boxID, toPath, trimTrailSlash(toPath)+"/%").Scan(&conflict); err != nil {
		return domain.FileEntry{}, err
	}
	if conflict != 0 {
		return domain.FileEntry{}, fmt.Errorf("target path already exists")
	}

	// Move the root entry.
	if _, err := tx.Exec(ctx, `
		UPDATE file_entries
		SET logical_path = $1, name = $2, parent_id = $3, updated_at = now()
		WHERE box_id = $4 AND logical_path = $5`,
		toPath, baseName(toPath), newParentID, boxID, fromPath); err != nil {
		return domain.FileEntry{}, err
	}

	// Rewrite descendants: replace the prefix in one statement. Descendants'
	// parent_id columns are unchanged because they still point at the same
	// (now-moved) parent rows; only logical_path moves.
	toPrefix := trimTrailSlash(toPath) + "/"
	if _, err := tx.Exec(ctx, `
		UPDATE file_entries
		SET logical_path = $1 || substring(logical_path FROM length($2) + 1),
		    updated_at = now()
		WHERE box_id = $3 AND logical_path LIKE $4`,
		toPrefix, fromPrefix, boxID, fromPrefix+"%"); err != nil {
		return domain.FileEntry{}, err
	}

	// Return the updated root entry.
	row := tx.QueryRow(ctx, `
		SELECT id, box_id, parent_id, logical_path, name, content_type, size_bytes, created_at
		FROM file_entries WHERE box_id = $1 AND logical_path = $2`, boxID, toPath)
	moved, err := scanEntry(row)
	if err != nil {
		return domain.FileEntry{}, err
	}
	return moved, tx.Commit(ctx)
}

func trimTrailSlash(p string) string {
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func (r *PGFileCatalog) GetFileEntry(ctx context.Context, fileID string) (domain.FileEntry, error) {
	return scanEntry(r.pool.QueryRow(ctx, `
		SELECT id, box_id, parent_id, logical_path, name, content_type, size_bytes, created_at
		FROM file_entries WHERE id = $1`, fileID))
}

func (r *PGFileCatalog) ListFiles(ctx context.Context, boxID string) ([]domain.FileEntry, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, box_id, parent_id, logical_path, name, content_type, size_bytes, created_at
		FROM file_entries WHERE box_id = $1 ORDER BY logical_path`, boxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.FileEntry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *PGFileCatalog) DeleteFileEntry(ctx context.Context, fileID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM file_entries WHERE id = $1`, fileID)
	return err
}

// DeleteEntryIfEmpty atomically removes the entry at logicalPath. Folders
// are only removed when they have no descendants. Stable sentinel errors —
// "not_found" and "folder_not_empty" — so callers can translate them to
// HTTP responses without string-matching DB messages.
func (r *PGFileCatalog) DeleteEntryIfEmpty(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.FileEntry{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT id, box_id, parent_id, logical_path, name, content_type, size_bytes, created_at
		FROM file_entries
		WHERE box_id = $1 AND logical_path = $2
		FOR UPDATE`, boxID, logicalPath)
	entry, err := scanEntry(row)
	if err != nil {
		if err.Error() == "file entry not found" {
			return domain.FileEntry{}, fmt.Errorf("not_found")
		}
		return domain.FileEntry{}, err
	}
	if entry.ContentType == folderContentType {
		var descendants int
		prefix := trimTrailSlash(logicalPath) + "/"
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM file_entries
			WHERE box_id = $1 AND logical_path LIKE $2`, boxID, prefix+"%").Scan(&descendants); err != nil {
			return domain.FileEntry{}, err
		}
		if descendants > 0 {
			return domain.FileEntry{}, fmt.Errorf("folder_not_empty")
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM file_entries WHERE id = $1`, entry.ID); err != nil {
		return domain.FileEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.FileEntry{}, err
	}
	return entry, nil
}

func (r *PGFileCatalog) GetByPath(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error) {
	return scanEntry(r.pool.QueryRow(ctx, `
		SELECT id, box_id, parent_id, logical_path, name, content_type, size_bytes, created_at
		FROM file_entries WHERE box_id = $1 AND logical_path = $2`, boxID, logicalPath))
}

func scanEntry(row interface {
	Scan(dest ...any) error
}) (domain.FileEntry, error) {
	var e domain.FileEntry
	var parent *string
	if err := row.Scan(&e.ID, &e.BoxID, &parent, &e.LogicalPath, &e.Name,
		&e.ContentType, &e.SizeBytes, &e.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.FileEntry{}, fmt.Errorf("file entry not found")
		}
		return domain.FileEntry{}, err
	}
	e.ParentID = parent
	return e, nil
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
