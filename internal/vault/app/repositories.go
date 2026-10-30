package app

import (
	"context"
	"time"

	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// BoxRepository is the persistence contract for `boxes`.
//
// Deletion is two-phase so that cross-subsystem cleanup (shares, audit)
// can finish BEFORE the row goes away. If we hard-deleted the box row
// up front, the FK CASCADE in migration 006 would drop every share
// row for it in the same transaction — leaving nothing for the worker
// to retry against.
//
//  1. SoftDelete — stamps `status='deleting'`, `deleted_at`,
//     `purge_requested_at`. The box is still queryable but the
//     service layer rejects new operations against it.
//  2. FinalizeDelete — the hard DELETE; FK CASCADE drops whatever
//     remains. Safe to call only after every dependent subsystem has
//     converged.
//
// The worker's BoxPurgeJob scans ListPurgeCandidates, drives dependent
// cleanup to done, then calls FinalizeDelete. The API only ever calls
// SoftDelete.
type BoxRepository interface {
	Put(ctx context.Context, box domain.Box) error
	Get(ctx context.Context, boxID string) (domain.Box, error)
	ListByOwner(ctx context.Context, ownerUserID string) ([]domain.Box, error)
	// Delete remains on the interface for test fixtures and the
	// memory-mode finalize path. Production API handlers MUST NOT
	// call it directly.
	Delete(ctx context.Context, boxID string) error

	SoftDelete(ctx context.Context, boxID string, now time.Time) error
	ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Box, error)
	FinalizeDelete(ctx context.Context, boxID string) error
}

type FileCatalogRepository interface {
	PutFileEntry(ctx context.Context, entry domain.FileEntry) error
	GetFileEntry(ctx context.Context, fileID string) (domain.FileEntry, error)
	ListFiles(ctx context.Context, boxID string) ([]domain.FileEntry, error)
	DeleteFileEntry(ctx context.Context, fileID string) error
	GetByPath(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error)
}
