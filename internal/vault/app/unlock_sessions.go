package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type UnlockSessionStore interface {
	Put(ctx context.Context, session domain.UnlockSession) error
	Get(ctx context.Context, sessionID string) (domain.UnlockSession, error)
	Delete(ctx context.Context, sessionID string) error
}
