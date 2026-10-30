package infra

import (
	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/platform/security"
)

// NewPasswordHasher returns the production hasher used by the identity
// service (argon2id with default parameters).
func NewPasswordHasher() app.PasswordHasher {
	return security.NewArgon2idHasher()
}
