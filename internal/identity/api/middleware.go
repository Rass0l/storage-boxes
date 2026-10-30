package api

import (
	"encoding/json"
	"net/http"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
)

// SessionCookieName is the name of the cookie used to carry the opaque session
// token.
const SessionCookieName = "sb_session"

// CSRFCookieName / CSRFHeaderName implement a double-submit CSRF defense.
const (
	CSRFCookieName = "sb_csrf"
	CSRFHeaderName = "X-CSRF-Token"
)

// RequireAuth wraps handlers that need an authenticated principal.
func RequireAuth(svc *app.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			writeAuthError(w, "no_session", "authentication required")
			return
		}
		user, roles, session, err := svc.Resolve(r.Context(), cookie.Value)
		if err != nil {
			clearSessionCookie(w)
			writeAuthError(w, "invalid_session", "authentication required")
			return
		}
		ctx := WithPrincipal(r.Context(), user, roles, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole MUST be composed under RequireAuth.
func RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !HasRole(r.Context(), role) {
			writeError(w, http.StatusForbidden, "forbidden", "role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF enforces the double-submit cookie pattern on state-changing
// requests.
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusForbidden, "csrf_missing", "csrf cookie required")
			return
		}
		header := r.Header.Get(CSRFHeaderName)
		if header == "" || header != cookie.Value {
			writeError(w, http.StatusForbidden, "csrf_mismatch", "csrf token mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeAuthError(w http.ResponseWriter, code, msg string) {
	writeError(w, http.StatusUnauthorized, code, msg)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(platerr.HTTPErrorResponse{
		Error: platerr.ErrorBody{Code: code, Message: msg},
	})
}
