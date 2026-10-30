package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type IdentityService interface {
	CreateUser(ctx context.Context, input CreateUserInput) (domain.User, error)
	Authenticate(ctx context.Context, email, password string) (domain.Session, error)
	RevokeSession(ctx context.Context, sessionID string) error
}

type CreateUserInput struct {
	Email       string
	DisplayName string
	Password    string
}
