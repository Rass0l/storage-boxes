package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	"github.com/Rass0l/storage-boxes/internal/platform/config"
	vaultapi "github.com/Rass0l/storage-boxes/internal/vault/api"
)

func buildTestApp(t *testing.T) *App {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("BOX_STORAGE_ROOT", tmp)
	t.Setenv("SEED_ADMIN_EMAIL", "admin@example.local")
	t.Setenv("SEED_ADMIN_PASSWORD", "admin-dev-password-change-me")
	cfg := config.Config{AppEnv: "test"}
	app, err := BuildApp(cfg, nil)
	if err != nil {
		t.Fatalf("build app: %v", err)
	}
	return app
}

type client struct {
	t       *testing.T
	handler http.Handler
	session *http.Cookie
	csrf    string
}

func (c *client) do(method, path string, body any, unlock string, raw []byte, ct string) *httptest.ResponseRecorder {
	c.t.Helper()
	var rdr *bytes.Reader
	if raw != nil {
		rdr = bytes.NewReader(raw)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	} else if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.session != nil {
		req.AddCookie(c.session)
	}
	if c.csrf != "" {
		req.AddCookie(&http.Cookie{Name: identityapi.CSRFCookieName, Value: c.csrf})
		if method != http.MethodGet {
			req.Header.Set(identityapi.CSRFHeaderName, c.csrf)
		}
	}
	if unlock != "" {
		req.Header.Set(vaultapi.UnlockHeaderName, unlock)
	}
	rr := httptest.NewRecorder()
	c.handler.ServeHTTP(rr, req)
	return rr
}

func TestEndToEndAuthAndBoxFlow(t *testing.T) {
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	// /auth/me without cookie -> 401
	rr := c.do(http.MethodGet, "/api/v1/auth/me", nil, "", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed /me: %d", rr.Code)
	}

	// Login as seeded admin.
	rr = c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	if c.session == nil || c.csrf == "" {
		t.Fatal("expected session + csrf cookies after login")
	}

	// /auth/me with cookie -> 200.
	rr = c.do(http.MethodGet, "/api/v1/auth/me", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("/me: %d %s", rr.Code, rr.Body.String())
	}

	// Admin route /users works because seeded admin has role admin.
	rr = c.do(http.MethodGet, "/api/v1/users", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list users: %d %s", rr.Code, rr.Body.String())
	}

	// Create a box.
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "e2e", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create box: %d %s", rr.Code, rr.Body.String())
	}
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	// Unlock.
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", rr.Code, rr.Body.String())
	}
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)

	// Upload.
	content := []byte("end-to-end encryption proof")
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/e2e.txt", nil, unlocked.SessionID, content, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	var up struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &up)

	// Download and verify round-trip.
	rr = c.do(http.MethodGet, "/api/v1/boxes/"+box.ID+"/files/"+up.Entry.ID+"/content", nil, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("download: %d", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Fatalf("content round-trip failed: got %q", rr.Body.String())
	}

	// Verify blob-on-disk is actually encrypted (not plaintext).
	storageRoot := os.Getenv("BOX_STORAGE_ROOT")
	blobPath := storageRoot + "/" + box.ID + "/" + up.Entry.ID
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob from disk: %v", err)
	}
	if strings.Contains(string(raw), "end-to-end encryption proof") {
		t.Fatalf("blob on disk appears to be plaintext")
	}

	// Logout.
	rr = c.do(http.MethodPost, "/api/v1/auth/logout", nil, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rr.Code, rr.Body.String())
	}

	// Session now invalid: /me returns 401.
	rr = c.do(http.MethodGet, "/api/v1/auth/me", nil, "", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /me: %d", rr.Code)
	}
}

func TestCSRFRequiredOnWrites(t *testing.T) {
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d", rr.Code)
	}
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == identityapi.SessionCookieName {
			c.session = ck
		}
		if ck.Name == identityapi.CSRFCookieName {
			c.csrf = ck.Value
		}
	}

	// Strip CSRF -> writes must 403.
	goodCSRF := c.csrf
	c.csrf = ""
	rr = c.do(http.MethodPost, "/api/v1/boxes",
		map[string]any{"name": "x", "size_bytes": 1024, "password": "boxpass1"}, "", nil, "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF, got %d: %s", rr.Code, rr.Body.String())
	}

	// Restore -> works.
	c.csrf = goodCSRF
	rr = c.do(http.MethodPost, "/api/v1/boxes",
		map[string]any{"name": "x", "size_bytes": 1024, "password": "boxpass1"}, "", nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 with CSRF, got %d", rr.Code)
	}
}
