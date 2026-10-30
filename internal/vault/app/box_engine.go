package app

import (
	"context"
	"io"
)

// BoxEngine owns physical box storage. It does not manage the file catalog
// (that lives in FileCatalogRepository) — it only handles the container
// lifecycle and raw encrypted blob IO. All file-level operations are
// driven through the vault Service which also owns the catalog.
type BoxEngine interface {
	CreateBox(ctx context.Context, boxID string, sizeBytes int64) error
	DeleteBox(ctx context.Context, boxID string) error
	UnlockBox(ctx context.Context, boxID string) error
	LockBox(ctx context.Context, boxID string) error

	// Blob primitives (identity of a blob == the catalog entry ID).
	WriteBlob(ctx context.Context, boxID, storageKey string, content io.Reader, key []byte) (int64, error)
	ReadBlob(ctx context.Context, boxID, storageKey string, key []byte) (io.ReadCloser, error)
	DeleteBlob(ctx context.Context, boxID, storageKey string) error
}
