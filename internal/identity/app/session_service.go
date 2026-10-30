package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type SessionService interface {
	Issue(ctx context.Context, user domain.User) (domain.Session, error)
	Current(ctx context.Context, sessionID string) (domain.Session, error)
	Revoke(ctx context.Context, sessionID string) error
}
