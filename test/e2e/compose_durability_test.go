//go:build compose_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// TestComposeRestartDurability proves the stores survive an api process
// restart and a docker restart. It also asserts the pg rows contain the
// expected shape (encrypted BMK, absolute expiry, etc) so we catch the
// class of bug where persistence "works" but stores garbage.
func TestComposeRestartDurability(t *testing.T) {
	if os.Getenv("COMPOSE_E2E") != "1" {
		t.Skip("set COMPOSE_E2E=1 to run compose-backed e2e tests")
	}
	requireDocker(t)

	s := newStack(t)
	s.up()
	t.Cleanup(s.down)

	waitReady(t, apiBase+"/healthz", 2*time.Minute)
	waitReady(t, apiBase+"/readyz", time.Minute)

	// --- First lifetime: log in, create a box, upload a file --------------

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	login := func() string {
		body, _ := json.Marshal(map[string]string{"email": seedEmail, "password": seedPass})
		req, _ := http.NewRequest(http.MethodPost, apiBase+"/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			raw, _ := io.ReadAll(res.Body)
			t.Fatalf("login status=%d body=%s", res.StatusCode, raw)
		}
		u, _ := url.Parse(apiBase)
		for _, c := range jar.Cookies(u) {
			if c.Name == "sb_csrf" {
				return c.Value
			}
		}
		t.Fatal("no csrf cookie after login")
		return ""
	}

	csrf := login()
	do := func(method, path string, body any, extra map[string]string) *http.Response {
		var rdr io.Reader
		if raw, ok := body.([]byte); ok {
			rdr = bytes.NewReader(raw)
		} else if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, apiBase+path, rdr)
		if extra["content-type"] != "" {
			req.Header.Set("Content-Type", extra["content-type"])
		} else if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		for k, v := range extra {
			if k == "content-type" {
				continue
			}
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return res
	}
	readBody := func(r *http.Response) []byte {
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return b
	}

	// Create a box.
	r := do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "durability-test", "size_bytes": 8192, "password": "boxpass1",
	}, nil)
	body := readBody(r)
	if r.StatusCode != 201 {
		t.Fatalf("create: %d %s", r.StatusCode, body)
	}
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &box)

	// Unlock + upload a file.
	r = do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, nil)
	body = readBody(r)
	if r.StatusCode != 200 {
		t.Fatalf("unlock: %d %s", r.StatusCode, body)
	}
	var un struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(body, &un)

	payload := []byte("durability payload " + time.Now().Format(time.RFC3339Nano))
	r = do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/d.txt",
		payload, map[string]string{"content-type": "text/plain", "X-Unlock-Session": un.SessionID})
	body = readBody(r)
	if r.StatusCode != 201 {
		t.Fatalf("upload: %d %s", r.StatusCode, body)
	}
	var up struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(body, &up)

	// --- pg introspection ------------------------------------------------

	// sessions has absolute_expires_at > now.
	if out := psql(t, "SELECT count(*) FROM sessions WHERE absolute_expires_at > now() AND user_id = 'usr_seed_admin'"); strings.TrimSpace(out) != "1" {
		t.Fatalf("expected one active session row, got %q", out)
	}
	// boxes row exists with matching owner.
	if out := psql(t, fmt.Sprintf("SELECT owner_user_id FROM boxes WHERE id = '%s'", box.ID)); strings.TrimSpace(out) != "usr_seed_admin" {
		t.Fatalf("box owner mismatch: %q", out)
	}
	// BMK is stored encrypted (bytea length 48 == 32-byte BMK + 16-byte GCM tag).
	if out := psql(t, fmt.Sprintf("SELECT length(wrapped_box_master_key) FROM box_crypto_material WHERE box_id = '%s'", box.ID)); strings.TrimSpace(out) != "48" {
		t.Fatalf("BMK ciphertext length unexpected: %q (want 48)", out)
	}
	// BMK ciphertext must NOT contain any obvious plaintext pattern.
	// The cipher output shouldn't equal the password, master key hex, or repeated bytes.
	if out := psql(t, fmt.Sprintf("SELECT encode(wrapped_box_master_key,'hex') FROM box_crypto_material WHERE box_id = '%s'", box.ID)); strings.Contains(out, "00000000000000000000") {
		t.Fatalf("BMK looks like zeroes, not ciphertext: %q", out)
	}
	// file_entries carries our entry with kind='file'.
	if out := psql(t, fmt.Sprintf("SELECT kind, logical_path FROM file_entries WHERE id = '%s'", up.Entry.ID)); !strings.Contains(out, "file") || !strings.Contains(out, "/d.txt") {
		t.Fatalf("file entry row missing/wrong: %q", out)
	}

	// --- Restart the API container and re-verify --------------------------

	if err := s.run("restart", "api"); err != nil {
		t.Fatalf("compose restart api: %v", err)
	}
	waitReady(t, apiBase+"/healthz", 60*time.Second)
	waitReady(t, apiBase+"/readyz", 30*time.Second)

	// Our existing session cookie should still resolve — the api restarted
	// but Postgres never lost the row.
	r = do(http.MethodGet, "/api/v1/auth/me", nil, nil)
	body = readBody(r)
	if r.StatusCode != 200 {
		t.Fatalf("post-restart /auth/me: %d %s", r.StatusCode, body)
	}

	// The box is listable.
	r = do(http.MethodGet, "/api/v1/boxes", nil, nil)
	body = readBody(r)
	if r.StatusCode != 200 || !strings.Contains(string(body), box.ID) {
		t.Fatalf("post-restart /boxes: %d %s", r.StatusCode, body)
	}

	// The in-process BMK cache was dropped by the restart — the old unlock
	// session must now refuse reads. Re-unlock and re-read the file.
	r = do(http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil,
		map[string]string{"X-Unlock-Session": un.SessionID})
	if r.StatusCode == 200 {
		readBody(r)
		t.Fatalf("stale unlock session was accepted post-restart — cache should have been invalidated")
	}
	readBody(r)

	r = do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, nil)
	body = readBody(r)
	if r.StatusCode != 200 {
		t.Fatalf("re-unlock post-restart: %d %s", r.StatusCode, body)
	}
	var un2 struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(body, &un2)

	r = do(http.MethodGet, "/api/v1/boxes/"+box.ID+"/files/"+up.Entry.ID+"/content", nil,
		map[string]string{"X-Unlock-Session": un2.SessionID})
	body = readBody(r)
	if r.StatusCode != 200 {
		t.Fatalf("post-restart read: %d %s", r.StatusCode, body)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("payload mismatch after restart: got %q want %q", body, payload)
	}
}

// psql executes a SQL statement against the running postgres container and
// returns the single-value result with header/formatting stripped.
func psql(t *testing.T, sql string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(),
		"docker", "exec", "compose-postgres-1", "psql",
		"-U", "postgres", "-d", "storage_boxes", "-tA", "-c", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var xerr *exec.ExitError
		if errors.As(err, &xerr) {
			t.Fatalf("psql %q failed: %v\n%s", sql, err, string(out))
		}
		t.Fatalf("psql: %v", err)
	}
	return strings.TrimSpace(string(out))
}
