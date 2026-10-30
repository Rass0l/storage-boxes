package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
)

// Deps bundles the services exposed by the identity API.
type Deps struct {
	Service       *app.Service
	SecureCookies bool
	IdleTimeout   time.Duration
}

func RegisterRoutes(mux *http.ServeMux, deps Deps) {
	if deps.IdleTimeout <= 0 {
		deps.IdleTimeout = 24 * time.Hour
	}
	h := &handlers{deps: deps}
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.HandleFunc("POST /api/v1/auth/logout", h.logout)
	mux.HandleFunc("GET /api/v1/auth/me", h.me)
	mux.Handle("GET /api/v1/users",
		RequireAuth(deps.Service, RequireRole("admin", http.HandlerFunc(h.listUsers))))
	mux.Handle("POST /api/v1/users",
		RequireAuth(deps.Service, RequireRole("admin", RequireCSRF(http.HandlerFunc(h.createUser)))))
}

type handlers struct{ deps Deps }

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	session, err := h.deps.Service.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	h.setSessionCookie(w, session.ID)
	csrf, err := h.setCSRFCookie(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "csrf_issue_failed", "unable to issue csrf token")
		return
	}
	user, roles, _, err := h.deps.Service.Resolve(r.Context(), session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_hydrate_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, LoginResponse{
		User:      toUserResponse(user, roles),
		CSRFToken: csrf,
	})
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		_ = h.deps.Service.RevokeSession(r.Context(), cookie.Value)
	}
	clearSessionCookie(w)
	h.clearCSRFCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "no_session", "not authenticated")
		return
	}
	user, roles, _, err := h.deps.Service.Resolve(r.Context(), cookie.Value)
	if err != nil {
		clearSessionCookie(w)
		writeError(w, http.StatusUnauthorized, "invalid_session", "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, MeResponse{User: toUserResponse(user, roles)})
}

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.deps.Service.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]UserResponse, 0, len(users))
	for _, u := range users {
		items = append(items, toUserResponse(u, nil))
	}
	writeJSON(w, http.StatusOK, UserListResponse{Items: items})
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	user, err := h.deps.Service.CreateUser(r.Context(), app.CreateUserInput{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Password:    req.Password,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toUserResponse(user, nil))
}

func (h *handlers) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.deps.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.deps.IdleTimeout.Seconds()),
	})
}

func (h *handlers) setCSRFCookie(w http.ResponseWriter) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   h.deps.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.deps.IdleTimeout.Seconds()),
	})
	return token, nil
}

func (h *handlers) clearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
}

func toUserResponse(u domain.User, roles []string) UserResponse {
	return UserResponse{
		ID:          u.ID,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Roles:       roles,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDomainError(w http.ResponseWriter, err error) {
	var de *platerr.DomainError
	if errors.As(err, &de) {
		writeError(w, platerr.HTTPStatus(de), de.Code, de.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal", err.Error())
}
