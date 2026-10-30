package api

import (
	"context"
	"encoding/json"
	"net/http"

	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/vault/app"
)

// UnlockHeaderName carries the unlock session ID on requests that read or
// write encrypted box contents.
const UnlockHeaderName = "X-Unlock-Session"

type ctxKey int

const (
	ctxKeyUnlock ctxKey = iota
)

func WithUnlock(ctx context.Context, uc app.UnlockContext) context.Context {
	return context.WithValue(ctx, ctxKeyUnlock, uc)
}

func UnlockFrom(ctx context.Context) (app.UnlockContext, bool) {
	v, ok := ctx.Value(ctxKeyUnlock).(app.UnlockContext)
	return v, ok && len(v.BMK) > 0
}

// RequireUnlockSession ensures the caller has an active unlock session bound
// to the box ID in the request path. Must be composed under
// identityapi.RequireAuth.
func RequireUnlockSession(svc *app.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := identityapi.UserFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "no_auth", "authentication required")
			return
		}
		sessionID := r.Header.Get(UnlockHeaderName)
		if sessionID == "" {
			writeError(w, http.StatusForbidden, "unlock_required", "box unlock session required")
			return
		}
		uc, err := svc.ResolveUnlock(r.Context(), sessionID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if uc.UserID != user.ID {
			writeError(w, http.StatusForbidden, "unlock_mismatch", "unlock session belongs to another user")
			return
		}
		boxID := r.PathValue("id")
		if boxID != "" && uc.BoxID != boxID {
			writeError(w, http.StatusForbidden, "unlock_wrong_box", "unlock session not for this box")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUnlock(r.Context(), uc)))
	})
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(platerr.HTTPErrorResponse{
		Error: platerr.ErrorBody{Code: code, Message: msg},
	})
}

func writeDomainError(w http.ResponseWriter, err error) {
	if de, ok := err.(*platerr.DomainError); ok {
		writeError(w, platerr.HTTPStatus(de), de.Code, de.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal", err.Error())
}
