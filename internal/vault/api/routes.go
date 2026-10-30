package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type Deps struct {
	Vault    *app.Service
	Identity *identityapp.Service
}

// RegisterRoutes wires vault endpoints. Requires an identity service for
// auth middleware composition.
func RegisterRoutes(mux *http.ServeMux, deps Deps) {
	h := &handlers{deps: deps}

	authed := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(deps.Identity, next)
	}
	writing := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(deps.Identity, identityapi.RequireCSRF(next))
	}
	unlocked := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(deps.Identity, RequireUnlockSession(deps.Vault, next))
	}
	unlockedWrite := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(deps.Identity,
			identityapi.RequireCSRF(RequireUnlockSession(deps.Vault, next)))
	}

	mux.Handle("GET /api/v1/boxes", authed(http.HandlerFunc(h.listBoxes)))
	mux.Handle("POST /api/v1/boxes", writing(http.HandlerFunc(h.createBox)))
	mux.Handle("DELETE /api/v1/boxes/{id}", writing(http.HandlerFunc(h.deleteBox)))
	mux.Handle("POST /api/v1/boxes/{id}/sessions", writing(http.HandlerFunc(h.unlock)))
	mux.Handle("DELETE /api/v1/boxes/{id}/sessions/{sessionId}", writing(http.HandlerFunc(h.lock)))

	mux.Handle("GET /api/v1/boxes/{id}/files", unlocked(http.HandlerFunc(h.listFiles)))
	mux.Handle("PUT /api/v1/boxes/{id}/files", unlockedWrite(http.HandlerFunc(h.putFile)))
	mux.Handle("GET /api/v1/boxes/{id}/files/{fileId}/content", unlocked(http.HandlerFunc(h.readFile)))
	mux.Handle("DELETE /api/v1/boxes/{id}/files", unlockedWrite(http.HandlerFunc(h.deleteFile)))
	mux.Handle("POST /api/v1/boxes/{id}/folders", unlockedWrite(http.HandlerFunc(h.createFolder)))
	mux.Handle("POST /api/v1/boxes/{id}/files/move", unlockedWrite(http.HandlerFunc(h.moveFile)))
}

type handlers struct{ deps Deps }

func (h *handlers) listBoxes(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	boxes, err := h.deps.Vault.ListBoxes(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]BoxResponse, 0, len(boxes))
	for _, b := range boxes {
		items = append(items, toBoxResponse(b))
	}
	writeJSON(w, http.StatusOK, BoxListResponse{Items: items})
}

func (h *handlers) createBox(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	var req CreateBoxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	box, err := h.deps.Vault.CreateBoxFull(r.Context(), app.CreateBoxFullInput{
		OwnerUserID: user.ID,
		Name:        req.Name,
		SizeBytes:   req.SizeBytes,
		Password:    req.Password,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toBoxResponse(box))
}

func (h *handlers) deleteBox(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	if err := h.deps.Vault.DeleteBox(r.Context(), r.PathValue("id"), user.ID); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) unlock(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	var req UnlockBoxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	session, err := h.deps.Vault.UnlockBox(r.Context(), r.PathValue("id"), user.ID, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UnlockResponse{SessionID: session.ID, ExpiresAt: session.ExpiresAt})
}

func (h *handlers) lock(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	if err := h.deps.Vault.LockBox(r.Context(), r.PathValue("id"), r.PathValue("sessionId"), user.ID); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := h.deps.Vault.ListFiles(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	items := make([]FileTreeItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, toFileItem(e))
	}
	writeJSON(w, http.StatusOK, FileTreeResponse{Items: items})
}

func (h *handlers) putFile(w http.ResponseWriter, r *http.Request) {
	uc, _ := UnlockFrom(r.Context())
	logicalPath := r.URL.Query().Get("path")
	contentType := r.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = "application/octet-stream"
	}
	entry, err := h.deps.Vault.PutFileWithKey(r.Context(), r.PathValue("id"), logicalPath, contentType, uc.BMK, r.Body)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, FileResponse{Entry: toFileItem(entry)})
}

func (h *handlers) readFile(w http.ResponseWriter, r *http.Request) {
	uc, _ := UnlockFrom(r.Context())
	entry, body, err := h.deps.Vault.ReadToBuffer(r.Context(), r.PathValue("id"), r.PathValue("fileId"), uc.BMK)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	ct := entry.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(body)), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, writerFromBytes(body))
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
func writerFromBytes(b []byte) io.Reader { return &byteReader{b: b} }

func (h *handlers) deleteFile(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if err := h.deps.Vault.DeleteByPath(r.Context(), r.PathValue("id"), p); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) createFolder(w http.ResponseWriter, r *http.Request) {
	var req CreateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	entry, err := h.deps.Vault.CreateFolderAt(r.Context(), r.PathValue("id"), req.LogicalPath)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, FileResponse{Entry: toFileItem(entry)})
}

func (h *handlers) moveFile(w http.ResponseWriter, r *http.Request) {
	var req MoveFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	entry, err := h.deps.Vault.MoveByPath(r.Context(), r.PathValue("id"), req.FromPath, req.ToPath)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, FileResponse{Entry: toFileItem(entry)})
}

func toBoxResponse(b domain.Box) BoxResponse {
	return BoxResponse{
		ID: b.ID, Name: b.Name, OwnerUserID: b.OwnerUserID,
		SizeBytes: b.SizeBytes, Status: b.Status, CreatedAt: b.CreatedAt,
	}
}

func toFileItem(e domain.FileEntry) FileTreeItem {
	kind := "file"
	if e.ContentType == "inode/directory" {
		kind = "folder"
	}
	return FileTreeItem{
		ID: e.ID, Name: e.Name, LogicalPath: e.LogicalPath,
		ContentType: e.ContentType, Kind: kind, SizeBytes: e.SizeBytes,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
