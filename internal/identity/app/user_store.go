package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

// UserStore persists users. Lookup is by email (unique) or ID.
type UserStore interface {
	Put(ctx context.Context, user domain.User) error
	GetByID(ctx context.Context, userID string) (domain.User, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	List(ctx context.Context) ([]domain.User, error)
}

// RoleStore manages role bindings for authorization.
type RoleStore interface {
	Bind(ctx context.Context, userID, role string) error
	Unbind(ctx context.Context, userID, role string) error
	RolesFor(ctx context.Context, userID string) ([]string, error)
}
