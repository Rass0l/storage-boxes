package api

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	ctxKeyRoles
	ctxKeySession
)

// WithPrincipal returns a derived context carrying the authenticated user,
// session, and role list.
func WithPrincipal(ctx context.Context, user domain.User, roles []string, session domain.Session) context.Context {
	ctx = context.WithValue(ctx, ctxKeyUser, user)
	ctx = context.WithValue(ctx, ctxKeyRoles, roles)
	ctx = context.WithValue(ctx, ctxKeySession, session)
	return ctx
}

func UserFrom(ctx context.Context) (domain.User, bool) {
	v, ok := ctx.Value(ctxKeyUser).(domain.User)
	return v, ok && v.ID != ""
}

func RolesFrom(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxKeyRoles).([]string); ok {
		return v
	}
	return nil
}

func SessionFrom(ctx context.Context) (domain.Session, bool) {
	v, ok := ctx.Value(ctxKeySession).(domain.Session)
	return v, ok && v.ID != ""
}

func HasRole(ctx context.Context, role string) bool {
	for _, r := range RolesFrom(ctx) {
		if r == role {
			return true
		}
	}
	return false
}
