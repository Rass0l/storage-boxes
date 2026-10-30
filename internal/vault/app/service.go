package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// VaultService is the narrow set of operations exposed to callers. File-level
// operations live on the concrete *Service so they can take and return the
// unwrapped BMK without leaking it through the interface.
type VaultService interface {
	CreateBox(ctx context.Context, input CreateBoxInput) (domain.Box, error)
	UnlockBox(ctx context.Context, boxID, userID, password string) (domain.UnlockSession, error)
	// LockBox requires the caller's user ID so we can enforce that only the
	// unlock session's own user can close it.
	LockBox(ctx context.Context, boxID, sessionID, requesterID string) error
	ListFiles(ctx context.Context, boxID string) ([]domain.FileEntry, error)
}

type CreateBoxInput struct {
	OwnerUserID string
	Name        string
	SizeBytes   int64
}
