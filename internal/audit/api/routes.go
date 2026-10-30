package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
)

// Deps wires the audit HTTP surface. Identity is required to gate reads
// behind an authenticated session (admin-only for cross-user queries).
type Deps struct {
	Service  app.AuditService
	Identity *identityapp.Service
}

// RegisterRoutes binds the audit HTTP endpoints. When deps.Service is nil a
// stub "not configured" list is returned so memory-mode tests stay green.
func RegisterRoutes(mux *http.ServeMux, deps ...Deps) {
	var d Deps
	if len(deps) > 0 {
		d = deps[0]
	}
	h := &handlers{deps: d}
	if d.Service == nil || d.Identity == nil {
		mux.HandleFunc("GET /api/v1/audit/events", h.stubList)
		return
	}
	mux.Handle("GET /api/v1/audit/events",
		identityapi.RequireAuth(d.Identity, http.HandlerFunc(h.list)))
	mux.Handle("GET /api/v1/audit/events/subject/{type}/{id}",
		identityapi.RequireAuth(d.Identity, http.HandlerFunc(h.listSubject)))
}

type handlers struct{ deps Deps }

func (h *handlers) stubList(w http.ResponseWriter, r *http.Request) {
	_ = r
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"items":[],"note":"audit service not configured"}`))
}

func (h *handlers) list(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	q := app.AuditQuery{
		SubjectType: r.URL.Query().Get("subject_type"),
		SubjectID:   r.URL.Query().Get("subject_id"),
		EventType:   r.URL.Query().Get("event_type"),
		ActorID:     r.URL.Query().Get("actor_id"),
	}
	// Non-admins are scoped to their own actor id.
	if !identityapi.HasRole(r.Context(), "admin") {
		q.ActorID = user.ID
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since = t
		}
	}
	events, err := h.deps.Service.List(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]AuditEventResponse, 0, len(events))
	for _, e := range events {
		items = append(items, toResponse(e))
	}
	writeJSON(w, http.StatusOK, AuditEventPageResponse{Items: items})
}

func (h *handlers) listSubject(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	q := app.AuditQuery{SubjectType: r.PathValue("type"), SubjectID: r.PathValue("id"), Limit: 100}
	if !identityapi.HasRole(r.Context(), "admin") {
		q.ActorID = user.ID
	}
	events, err := h.deps.Service.List(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]AuditEventResponse, 0, len(events))
	for _, e := range events {
		items = append(items, toResponse(e))
	}
	writeJSON(w, http.StatusOK, AuditEventPageResponse{Items: items})
}

func toResponse(e domain.AuditEvent) AuditEventResponse {
	return AuditEventResponse{
		ID:          e.ID,
		EventType:   e.EventType,
		SubjectType: e.SubjectType,
		SubjectID:   e.SubjectID,
		ActorID:     e.ActorID,
		OccurredAt:  e.OccurredAt.Format(time.RFC3339),
		Metadata:    e.Metadata,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
