package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type CredentialStore interface {
	Put(ctx context.Context, credential domain.Credential) error
	GetByUserID(ctx context.Context, userID string) (domain.Credential, error)
	GetByEmail(ctx context.Context, email string) (domain.Credential, error)
}
