//go:build compose_e2e

// Package e2e holds the compose-backed end-to-end test. It brings up the
// full docker compose stack, drives the API through the major user flows,
// and tears everything down.
//
// Gated by the `compose_e2e` build tag so `go test ./...` stays fast.
// Run with: `go test -tags=compose_e2e ./test/e2e/... -run TestCompose -v -timeout 10m`
// or via `make compose-e2e`.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	apiBase   = "http://localhost:8082"
	feBase    = "http://localhost:5173"
	seedEmail = "admin@example.local"
	seedPass  = "admin-dev-password-change-me"
)

// stack is a thin shim kept for backwards compatibility with the original
// compose tests. Actual lifecycle now lives in compose_helpers.go; the
// shared stack is brought up once per `go test` invocation and torn down
// by TestMain.
type stack struct{ t *testing.T }

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	out, err := exec.Command("docker", "info").CombinedOutput()
	if err != nil {
		t.Skipf("docker daemon not reachable: %v\n%s", err, string(out))
	}
}

func newStack(t *testing.T) *stack        { return &stack{t: t} }
func (s *stack) up()                      { ensureSharedStack(s.t) }
func (s *stack) down()                    { /* handled by TestMain */ }
func (s *stack) run(args ...string) error { return runCompose(s.t, sharedDir, args...) }

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func waitReady(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := http.Get(url)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s not ready after %s", url, timeout)
}

type apiClient struct {
	t    *testing.T
	c    *http.Client
	csrf string
}

func newAPIClient(t *testing.T) *apiClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &apiClient{t: t, c: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func (a *apiClient) rememberCSRF() {
	u, _ := url.Parse(apiBase)
	for _, c := range a.c.Jar.Cookies(u) {
		if c.Name == "sb_csrf" {
			a.csrf = c.Value
			return
		}
	}
}

func (a *apiClient) do(method, path string, body any, opts ...func(*http.Request)) (*http.Response, []byte) {
	a.t.Helper()
	var rdr io.Reader
	if raw, ok := body.([]byte); ok {
		rdr = bytes.NewReader(raw)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, apiBase+path, rdr)
	if err != nil {
		a.t.Fatalf("new req: %v", err)
	}
	switch body.(type) {
	case []byte, nil:
		// no-op; caller sets Content-Type via opts
	default:
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	for _, o := range opts {
		o(req)
	}
	res, err := a.c.Do(req)
	if err != nil {
		a.t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res, data
}

func TestComposeStackMajorFlows(t *testing.T) {
	if os.Getenv("COMPOSE_E2E") != "1" {
		t.Skip("set COMPOSE_E2E=1 to run compose-backed e2e tests")
	}
	requireDocker(t)

	s := newStack(t)
	s.up()
	t.Cleanup(s.down)

	waitReady(t, apiBase+"/healthz", 2*time.Minute)
	waitReady(t, apiBase+"/readyz", time.Minute)
	waitReady(t, feBase+"/healthz", 30*time.Second)

	api := newAPIClient(t)

	// 1. /auth/me anonymous -> 401
	res, body := api.do(http.MethodGet, "/api/v1/auth/me", nil)
	if res.StatusCode != 401 {
		t.Fatalf("anon /me: %d %s", res.StatusCode, body)
	}

	// 2. Login with seeded admin.
	res, body = api.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": seedEmail, "password": seedPass})
	if res.StatusCode != 200 {
		t.Fatalf("login: %d %s", res.StatusCode, body)
	}
	api.rememberCSRF()
	if api.csrf == "" {
		t.Fatal("expected sb_csrf cookie after login")
	}

	// 3. /auth/me authenticated.
	res, body = api.do(http.MethodGet, "/api/v1/auth/me", nil)
	if res.StatusCode != 200 {
		t.Fatalf("authed /me: %d %s", res.StatusCode, body)
	}

	// 4. Admin /users reachable.
	res, body = api.do(http.MethodGet, "/api/v1/users", nil)
	if res.StatusCode != 200 {
		t.Fatalf("/users: %d %s", res.StatusCode, body)
	}

	// 5. Create a box.
	res, body = api.do(http.MethodPost, "/api/v1/boxes",
		map[string]any{"name": "compose-e2e", "size_bytes": 4096, "password": "boxpass1"})
	if res.StatusCode != 201 {
		t.Fatalf("create box: %d %s", res.StatusCode, body)
	}
	var box struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &box); err != nil || box.ID == "" {
		t.Fatalf("parse box: %v (%s)", err, body)
	}

	// 6. Unlock.
	res, body = api.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"})
	if res.StatusCode != 200 {
		t.Fatalf("unlock: %d %s", res.StatusCode, body)
	}
	var un struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(body, &un)
	if un.SessionID == "" {
		t.Fatalf("empty unlock session: %s", body)
	}
	unlockHeader := func(r *http.Request) { r.Header.Set("X-Unlock-Session", un.SessionID) }

	// 7. Upload a file.
	payload := []byte("compose e2e encryption round-trip " + time.Now().Format(time.RFC3339Nano))
	res, body = api.do(http.MethodPut,
		"/api/v1/boxes/"+box.ID+"/files?path=/hello.txt",
		payload,
		unlockHeader,
		func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
	)
	if res.StatusCode != 201 {
		t.Fatalf("upload: %d %s", res.StatusCode, body)
	}
	var up struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(body, &up)
	if up.Entry.ID == "" {
		t.Fatalf("upload returned no entry id: %s", body)
	}

	// 8. List files.
	res, body = api.do(http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil, unlockHeader)
	if res.StatusCode != 200 {
		t.Fatalf("list files: %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "/hello.txt") {
		t.Fatalf("list missing hello.txt: %s", body)
	}

	// 9. Download and match bytes.
	res, body = api.do(http.MethodGet,
		"/api/v1/boxes/"+box.ID+"/files/"+up.Entry.ID+"/content", nil, unlockHeader)
	if res.StatusCode != 200 {
		t.Fatalf("download: %d %s", res.StatusCode, body)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("content round-trip failed: got %q, want %q", body, payload)
	}

	// 10. Create folder + move.
	res, body = api.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/folders",
		map[string]string{"logical_path": "/archive"}, unlockHeader)
	if res.StatusCode != 201 {
		t.Fatalf("folder: %d %s", res.StatusCode, body)
	}
	res, body = api.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/files/move",
		map[string]string{"from_path": "/hello.txt", "to_path": "/archive/hello.txt"}, unlockHeader)
	if res.StatusCode != 200 {
		t.Fatalf("move: %d %s", res.StatusCode, body)
	}

	// 11. Delete + lock.
	deleteReq := func(r *http.Request) { /* unlock header set above */ }
	res, body = api.do(http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/files?path=/archive/hello.txt", nil, unlockHeader, deleteReq)
	if res.StatusCode != 204 {
		t.Fatalf("delete file: %d %s", res.StatusCode, body)
	}
	res, _ = api.do(http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/sessions/"+un.SessionID, nil)
	if res.StatusCode != 204 {
		t.Fatalf("lock: %d", res.StatusCode)
	}

	// 12. Logout.
	res, _ = api.do(http.MethodPost, "/api/v1/auth/logout", nil)
	if res.StatusCode != 204 {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	// Clear csrf since session is gone.
	api.csrf = ""
	res, _ = api.do(http.MethodGet, "/api/v1/auth/me", nil)
	if res.StatusCode != 401 {
		t.Fatalf("post-logout /me: %d", res.StatusCode)
	}

	// 13. Frontend is serving the SPA shell (not just /healthz).
	fres, err := http.Get(feBase + "/")
	if err != nil {
		t.Fatalf("frontend GET /: %v", err)
	}
	feBody, _ := io.ReadAll(fres.Body)
	_ = fres.Body.Close()
	if fres.StatusCode != 200 || !bytes.Contains(feBody, []byte("<div id=\"root\"")) {
		t.Fatalf("frontend did not serve SPA shell: status=%d body=%.200s", fres.StatusCode, feBody)
	}

	fmt.Fprintln(testWriter{t}, "compose e2e flow passed")
}
