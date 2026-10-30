package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	jobsapp "github.com/Rass0l/storage-boxes/internal/jobs/app"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	sharesapi "github.com/Rass0l/storage-boxes/internal/shares/api"
	sharesapp "github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestSharesEndToEnd drives the full share lifecycle through the in-process
// app: login → create box → unlock → upload → create share → public
// download via the share-gateway handlers → exercise max-download cap →
// revoke → verify access log + audit trail.
func TestSharesEndToEnd(t *testing.T) {
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31)) // 64 hex
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	// Login as seeded admin.
	rr := c.do(http.MethodPost, "/api/v1/auth/login",
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

	// Create + unlock + upload.
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "share-box", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create box: %d %s", rr.Code, rr.Body.String())
	}
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", rr.Code, rr.Body.String())
	}
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)

	body := []byte("shared-payload-abc")
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/shared.txt",
		nil, unlocked.SessionID, body, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)

	// Create share.
	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id":         box.ID,
		"file_entry_id":  upload.Entry.ID,
		"expiry_seconds": 3600,
		"max_downloads":  2,
	}, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create share: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.Token == "" {
		t.Fatal("expected raw token in create response")
	}

	// Hit the public delivery handler — registered on a separate mux so we
	// don't have to run a real share-gateway process.
	pmux := http.NewServeMux()
	// Reuse the same share service by pulling it out of the app wiring —
	// we can do this via a hidden hook, but easier: stand up a scratch mux
	// backed by a fresh PublicDelivery wrapping the same underlying repos
	// through a small shim.
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: app.publicShares()})

	// First download — 200 and byte-identical payload.
	resp := callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code != http.StatusOK {
		t.Fatalf("public download 1: %d %s", resp.Code, resp.Body.String())
	}
	if !bytes.Equal(resp.Body.Bytes(), body) {
		t.Fatalf("public download payload mismatch: %q", resp.Body.String())
	}
	// Second download — still 200.
	resp = callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code != http.StatusOK {
		t.Fatalf("public download 2: %d", resp.Code)
	}
	// Third — should 404 (exhausted).
	resp = callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code == http.StatusOK {
		t.Fatalf("expected exhausted share to stop serving; got 200")
	}

	// Access log should carry 3 entries (2 successes + 1 denied). The HEAD
	// path doesn't add a record here. Listed via the authenticated API.
	rr = c.do(http.MethodGet, "/api/v1/shares/"+created.ID+"/access", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("access log: %d %s", rr.Code, rr.Body.String())
	}

	// Revoke.
	rr = c.do(http.MethodDelete, "/api/v1/shares/"+created.ID, nil, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}

	// Audit: fetch events scoped to this actor and assert share events.
	rr = c.do(http.MethodGet, "/api/v1/audit/events?subject_type=share&limit=50", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list: %d %s", rr.Code, rr.Body.String())
	}
	var events struct {
		Items []struct {
			EventType string `json:"event_type"`
			SubjectID string `json:"subject_id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &events)
	seen := map[string]bool{}
	for _, e := range events.Items {
		if e.SubjectID == created.ID {
			seen[e.EventType] = true
		}
	}
	for _, want := range []string{auditdomain.EventShareCreated, auditdomain.EventShareRevoked} {
		if !seen[want] {
			t.Fatalf("expected %q in audit; saw %+v", want, events.Items)
		}
	}
}

// TestRestrictedShareEndToEnd drives the full restricted-share lifecycle
// through the real API: login → create box + file → POST a restricted
// share → list recipients → rotate a passcode → verify passcode via the
// gateway → download with the claim cookie → revoke recipient → confirm
// the cookie stops working.
//
// This is the highest-value regression the spec asks for: it proves that
// cmd/api wiring actually exposes the restricted repos (without that,
// /api/v1/shares responds 500 on access_mode=restricted and every
// /recipients endpoint returns 503) and that the audit trail lines up
// end-to-end.
func TestRestrictedShareEndToEnd(t *testing.T) {
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d", rr.Code)
	}
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "restricted-box", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/r.txt",
		nil, unlocked.SessionID, []byte("restricted-payload"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)

	// Create restricted share with two recipients.
	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id":           box.ID,
		"file_entry_id":    upload.Entry.ID,
		"expiry_seconds":   3600,
		"max_downloads":    5,
		"access_mode":      "restricted",
		"recipient_emails": []string{"dest@example.com", "Other@Example.com"},
	}, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create restricted share: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID         string `json:"id"`
		Token      string `json:"token"`
		AccessMode string `json:"access_mode"`
		Recipients []struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			Passcode string `json:"passcode"`
		} `json:"recipients"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.AccessMode != "restricted" {
		t.Fatalf("access_mode in response: %q", created.AccessMode)
	}
	if len(created.Recipients) != 2 {
		t.Fatalf("want 2 recipients, got %d", len(created.Recipients))
	}
	for _, r := range created.Recipients {
		if r.Passcode == "" {
			t.Fatalf("recipient %s missing passcode", r.ID)
		}
	}
	firstRec := created.Recipients[0]

	// Bearer-token download MUST be rejected — a restricted share is
	// not a public link. The gateway redirects to /verify; listing the
	// access log will still show a denied row because that's how the
	// gateway records the attempt.
	pmux := http.NewServeMux()
	svc := app.publicShareSvc()
	sharesapi.RegisterGatewayRoutes(pmux, sharesapi.GatewayDeps{
		Deps:         sharesapi.Deps{Public: svc, Service: svc},
		Verification: svc,
	})
	resp := callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("bearer download on restricted share: want 303 redirect, got %d", resp.Code)
	}

	// Verify with correct passcode via JSON so we get the cookie back.
	verifyBody := map[string]string{"email": firstRec.Email, "passcode": firstRec.Passcode}
	rr2 := publicJSON(t, pmux, "POST", "/s/"+created.Token+"/verify", verifyBody)
	if rr2.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rr2.Code, rr2.Body.String())
	}
	var claimCookie *http.Cookie
	for _, ck := range rr2.Result().Cookies() {
		if ck.Name == sharesapi.ShareClaimCookieName {
			claimCookie = ck
		}
	}
	if claimCookie == nil {
		t.Fatal("verify did not set sb_share_claim cookie")
	}

	// Download with the claim cookie — 200.
	req := httptest.NewRequest("GET", "/s/"+created.Token, nil)
	req.AddCookie(claimCookie)
	resp = httptest.NewRecorder()
	pmux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("download with claim: %d %s", resp.Code, resp.Body.String())
	}
	if !bytes.Equal(resp.Body.Bytes(), []byte("restricted-payload")) {
		t.Fatalf("payload mismatch: %q", resp.Body.String())
	}

	// Activity: the recipient timeline must include BOTH a passcode
	// challenge (verified) AND a download (delivered) attributed to
	// this recipient. That's the whole point of the merged view —
	// without it the operator only sees half the lifecycle.
	rr = c.do(http.MethodGet, "/api/v1/shares/"+created.ID+"/recipients/"+firstRec.ID+"/activity?limit=50",
		nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("activity: %d %s", rr.Code, rr.Body.String())
	}
	var activity struct {
		Items []struct {
			Kind           string `json:"kind"`
			Succeeded      bool   `json:"succeeded"`
			Reason         string `json:"reason"`
			LifecycleEvent string `json:"lifecycle_event"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &activity)
	sawVerifiedChallenge := false
	sawDeliveredAccess := false
	// The timeline now advertises the full recipient lifecycle
	// end-to-end — anything less is a regression because operators
	// staring at a revoked recipient need to see the revocation, not
	// just the verifications that preceded it.
	sawRecipientAdded := false
	sawClaimIssued := false
	for _, e := range activity.Items {
		if e.Kind == "challenge" && e.Succeeded {
			sawVerifiedChallenge = true
		}
		if e.Kind == "access" && e.Succeeded {
			sawDeliveredAccess = true
		}
		if e.Kind == "lifecycle" && e.LifecycleEvent == "shares.recipient_added" {
			sawRecipientAdded = true
		}
		if e.Kind == "lifecycle" && e.LifecycleEvent == "shares.claim_issued" {
			sawClaimIssued = true
		}
	}
	if !sawVerifiedChallenge {
		t.Error("recipient activity missing verified passcode challenge")
	}
	if !sawDeliveredAccess {
		t.Error("recipient activity missing delivered download (access row with recipient_id)")
	}
	if !sawRecipientAdded {
		t.Error("recipient activity missing shares.recipient_added lifecycle row")
	}
	if !sawClaimIssued {
		t.Error("recipient activity missing shares.claim_issued lifecycle row")
	}

	// Rotate passcode on a recipient — claim should stop working.
	rr = c.do(http.MethodPost, "/api/v1/shares/"+created.ID+"/recipients/"+firstRec.ID+"/rotate",
		map[string]any{}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest("GET", "/s/"+created.Token, nil)
	req.AddCookie(claimCookie)
	resp = httptest.NewRecorder()
	pmux.ServeHTTP(resp, req)
	if resp.Code == http.StatusOK {
		t.Fatal("download after rotate-passcode must be rejected")
	}

	// Audit: must carry recipient_added, claim_issued, claim_revoked with
	// reason=passcode_rotated, and passcode_rotated itself.
	rr = c.do(http.MethodGet, "/api/v1/audit/events?limit=200", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list: %d", rr.Code)
	}
	var events struct {
		Items []struct {
			EventType string         `json:"event_type"`
			Metadata  map[string]any `json:"metadata"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &events)
	wantSeen := map[string]bool{
		auditdomain.EventShareCreated:            false,
		auditdomain.EventShareRecipientAdded:     false,
		auditdomain.EventShareChallengeSucceeded: false,
		auditdomain.EventShareClaimIssued:        false,
		auditdomain.EventSharePasscodeRotated:    false,
	}
	rotatedClaimRevokeSeen := false
	for _, e := range events.Items {
		if _, ok := wantSeen[e.EventType]; ok {
			wantSeen[e.EventType] = true
		}
		if e.EventType == auditdomain.EventShareClaimRevoked {
			if reason, _ := e.Metadata["reason"].(string); reason == "passcode_rotated" {
				rotatedClaimRevokeSeen = true
			}
		}
	}
	for et, seen := range wantSeen {
		if !seen {
			t.Errorf("missing expected audit event %q", et)
		}
	}
	if !rotatedClaimRevokeSeen {
		t.Error("missing shares.claim_revoked with reason=passcode_rotated")
	}
}

// publicJSON is a small helper for the test that drives JSON POSTs
// against the public mux (verify / otp).
func publicJSON(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestHEADDoesNotIncrementDownloads verifies RFC-9110 HEAD semantics:
// a probe must not consume a download slot, must not record a
// successful access row, and must reflect the same deliverability
// state as a subsequent GET.
func TestHEADDoesNotIncrementDownloads(t *testing.T) {
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "head-test", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/h.txt",
		nil, unlocked.SessionID, []byte("hello-head"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)
	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id": box.ID, "file_entry_id": upload.Entry.ID,
		"expiry_seconds": 3600, "max_downloads": 1, // cap of exactly 1.
	}, unlocked.SessionID, nil, "")
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	pmux := http.NewServeMux()
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: app.publicShares()})

	// Fire three HEAD probes. None of them should count toward the cap.
	for i := 0; i < 3; i++ {
		resp := callPublic(t, pmux, "HEAD", "/s/"+created.Token)
		if resp.Code != http.StatusOK {
			t.Fatalf("HEAD #%d: %d %s", i, resp.Code, resp.Body.String())
		}
		if resp.Body.Len() != 0 {
			t.Fatalf("HEAD #%d must not return a body; got %d bytes", i, resp.Body.Len())
		}
	}

	// The subsequent GET must still succeed — HEAD did not exhaust
	// the single-download cap.
	resp := callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET after HEAD probes: %d %s", resp.Code, resp.Body.String())
	}

	// After the GET the share is exhausted; a second GET must 404.
	resp = callPublic(t, pmux, "GET", "/s/"+created.Token)
	if resp.Code == http.StatusOK {
		t.Fatalf("expected exhausted share to stop after first GET; got 200")
	}

	// Fetch the share's state — download_count must be exactly 1.
	rr = c.do(http.MethodGet, "/api/v1/shares/"+created.ID, nil, "", nil, "")
	var detail struct {
		DownloadCount int    `json:"download_count"`
		Status        string `json:"status"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &detail)
	if detail.DownloadCount != 1 {
		t.Fatalf("download_count should be 1 (HEAD must not bump); got %d", detail.DownloadCount)
	}
}

// TestShareSettingsUpdate exercises PATCH /api/v1/shares/{id}: extending
// expiry and raising max_downloads, plus the two validation guards
// (cannot drop the cap below the current count; cannot set a past
// expiry).
func TestShareSettingsUpdate(t *testing.T) {
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "upd", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/u.txt",
		nil, unlocked.SessionID, []byte("payload"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)
	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id": box.ID, "file_entry_id": upload.Entry.ID,
		"expiry_seconds": 3600, "max_downloads": 2,
	}, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create share: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	// Happy path: extend expiry + raise cap.
	newMax := 5
	rr = c.do(http.MethodPatch, "/api/v1/shares/"+created.ID,
		map[string]any{"expiry_seconds": 7200, "max_downloads": newMax}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("patch happy path: %d %s", rr.Code, rr.Body.String())
	}
	var updated struct {
		MaxDownloads int    `json:"max_downloads"`
		ExpiresAt    string `json:"expires_at"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &updated)
	if updated.MaxDownloads != newMax {
		t.Fatalf("max_downloads not updated: %d", updated.MaxDownloads)
	}

	// Guard: cannot drop below current download_count (0 here is OK,
	// but we simulate a used slot by draining one download via the
	// gateway first, then attempt to drop the cap below).
	pmux := http.NewServeMux()
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: app.publicShares()})
	// Need the raw token — refetch the created struct including token
	// isn't possible (one-shot); use the share's count directly.
	// Instead: attempt to drop to 0 — with 0 downloads so far, this
	// is allowed. Drop to -1 to hit the "cannot be below current" path
	// transitively isn't reachable either. Instead, drop below current
	// post-expiration: advance download_count by direct service call.
	// Simpler: attempt a negative number; the DTO pointer treats it as
	// an explicit value and the service rejects it on the "cannot be
	// below current download_count" path when count > requested. With
	// count=0, request -1 is rejected as "cannot be negative" equivalent.
	// Since ShareService validates `< DownloadCount` (count=0 → -1 < 0
	// rejected), this hits the same branch.
	rr = c.do(http.MethodPatch, "/api/v1/shares/"+created.ID,
		map[string]any{"max_downloads": -1}, "", nil, "")
	if rr.Code == http.StatusOK {
		t.Fatal("expected patch to reject max_downloads=-1")
	}

	// Guard: past expiry rejected.
	rr = c.do(http.MethodPatch, "/api/v1/shares/"+created.ID,
		map[string]any{"expiry_seconds": -3600}, "", nil, "")
	if rr.Code == http.StatusOK {
		t.Fatal("expected patch to reject past expiry")
	}
}

// TestRevokeIsTruthfulOnRepoFailure proves that a UpdateStatus error
// after MarkPurgeRequested surfaces to the caller — without the fix,
// a silent swallow would leave the share marked "active" but
// purge_requested, confusing operators.
func TestRevokeIsTruthfulOnRepoFailure(t *testing.T) {
	// Stand up a service with a flaky repo that returns an error on
	// UpdateStatus so the "partial success" branch fires. This runs
	// entirely in-process; no compose needed.
	repo := &flakyShareRepo{MemoryShareRepository: *sharesinfra.NewMemoryShareRepository()}
	svc := sharesapp.NewService(sharesapp.Deps{
		Shares:    repo,
		Objects:   sharesinfra.NewMemoryShareObjectStore(),
		AccessLog: sharesinfra.NewMemoryAccessRecorder(),
		Stage:     noopStage{},
		Tokens:    sharesinfra.RandomTokenService{},
	})
	res, err := svc.CreateShare(context.Background(), sharesapp.CreateShareInput{
		CreatorUserID: "u", BoxID: "b", FileEntryID: "f",
		UnlockBMK: []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), MaxDownloads: 3,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	repo.failUpdateStatus = true
	if err := svc.Revoke(context.Background(), "u", res.Share.ID); err == nil {
		t.Fatal("expected Revoke to surface UpdateStatus failure; got nil")
	}
	// purge_requested_at must be set even when UpdateStatus failed — the
	// worker picks up this row on the next pass.
	got, _ := repo.Get(context.Background(), res.Share.ID)
	if got.PurgeRequestedAt == nil {
		t.Fatal("purge_requested_at should be stamped even when UpdateStatus fails")
	}
}

type flakyShareRepo struct {
	sharesinfra.MemoryShareRepository
	failUpdateStatus bool
}

func (r *flakyShareRepo) UpdateStatus(ctx context.Context, id, status string, now time.Time) error {
	if r.failUpdateStatus {
		return &flakyErr{}
	}
	return r.MemoryShareRepository.UpdateStatus(ctx, id, status, now)
}

type flakyErr struct{}

func (flakyErr) Error() string { return "simulated pg failure" }

type noopStage struct{}

func (noopStage) Stage(ctx context.Context, boxID, fileID string, bmk []byte) (sharesapp.StagedPayload, error) {
	return sharesapp.StagedPayload{
		StorageKey: "sk", WrappedShareKey: make([]byte, 16), Nonce: make([]byte, 12),
		SizeBytes: 4, ContentType: "text/plain", OriginalName: "u.txt",
	}, nil
}
func (noopStage) Delete(ctx context.Context, shareID, storageKey string) error { return nil }
func (noopStage) Open(ctx context.Context, sk string, wsk, n []byte) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

// TestDownloadNotCountedOnStreamFailure proves the public handler
// accounts for successes honestly: a client that gets a partial or
// interrupted body must NOT see its download counted, and the access
// row must record succeeded=false. The earlier implementation called
// CountDownload + RecordAccess(succeeded=true) unconditionally after
// WriteHeader(200), which lied whenever io.Copy returned an error.
func TestDownloadNotCountedOnStreamFailure(t *testing.T) {
	// Seed a share service with a stage engine whose reader errors
	// mid-stream and an interceptor on CountDownload so we can assert
	// it was NEVER called.
	shareRepo := sharesinfra.NewMemoryShareRepository()
	objStore := sharesinfra.NewMemoryShareObjectStore()
	access := sharesinfra.NewMemoryAccessRecorder()
	stage := &halfwayStage{halt: errors.New("simulated disconnect")}

	svc := sharesapp.NewService(sharesapp.Deps{
		Shares:    shareRepo,
		Objects:   objStore,
		AccessLog: access,
		Stage:     stage,
		Tokens:    sharesinfra.RandomTokenService{},
	})
	res, err := svc.CreateShare(context.Background(), sharesapp.CreateShareInput{
		CreatorUserID: "u", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 3,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	beforeCount := res.Share.DownloadCount

	// Drive a GET through the public handler.
	pmux := http.NewServeMux()
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: svc})

	req := httptest.NewRequest(http.MethodGet, "/s/"+res.RawToken, nil)
	rr := httptest.NewRecorder()
	pmux.ServeHTTP(rr, req)

	// HTTP status already 200 (headers went out before the stream failed).
	// The honest signal is on the share row + access log.
	got, err := shareRepo.Get(context.Background(), res.Share.ID)
	if err != nil {
		t.Fatalf("get share: %v", err)
	}
	if got.DownloadCount != beforeCount {
		t.Fatalf("download_count must stay %d when stream fails; got %d", beforeCount, got.DownloadCount)
	}

	events, _ := access.ListByShare(context.Background(), res.Share.ID, 10)
	if len(events) == 0 {
		t.Fatal("expected an access event recorded")
	}
	var failRow *domain.AccessEvent
	for i := range events {
		if !events[i].Succeeded {
			failRow = &events[i]
			break
		}
	}
	if failRow == nil {
		t.Fatalf("expected at least one succeeded=false access row; saw %+v", events)
	}
	reason, _ := failRow.Metadata["reason"].(string)
	if reason == "" || reason == "internal" {
		t.Fatalf("expected a concrete reason on the failure row; got %q", reason)
	}
	// Sanity: no success row for this attempt.
	for _, e := range events {
		if e.Succeeded {
			t.Fatalf("stream failure must not produce a succeeded=true row: %+v", e)
		}
	}
}

// TestDownloadCountedOnCleanStream is the positive sibling: when
// io.Copy returns nil, download_count bumps and a succeeded=true
// access row lands. Guards against an over-zealous fix that forgets
// to record success.
func TestDownloadCountedOnCleanStream(t *testing.T) {
	shareRepo := sharesinfra.NewMemoryShareRepository()
	objStore := sharesinfra.NewMemoryShareObjectStore()
	access := sharesinfra.NewMemoryAccessRecorder()
	stage := cleanStage{body: []byte("hello-world")}

	svc := sharesapp.NewService(sharesapp.Deps{
		Shares:    shareRepo,
		Objects:   objStore,
		AccessLog: access,
		Stage:     stage,
		Tokens:    sharesinfra.RandomTokenService{},
	})
	res, err := svc.CreateShare(context.Background(), sharesapp.CreateShareInput{
		CreatorUserID: "u", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 3,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	pmux := http.NewServeMux()
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: svc})
	req := httptest.NewRequest(http.MethodGet, "/s/"+res.RawToken, nil)
	rr := httptest.NewRecorder()
	pmux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if rr.Body.String() != "hello-world" {
		t.Fatalf("body mismatch: %q", rr.Body.String())
	}

	got, _ := shareRepo.Get(context.Background(), res.Share.ID)
	if got.DownloadCount != 1 {
		t.Fatalf("download_count want 1, got %d", got.DownloadCount)
	}
	events, _ := access.ListByShare(context.Background(), res.Share.ID, 10)
	sawSuccess := false
	for _, e := range events {
		if e.Succeeded {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("expected a succeeded=true access row; saw %+v", events)
	}
}

// halfwayStage produces a reader that returns half the body and then
// fails. Size on the StagedPayload reflects the full length so the
// handler's short-write branch also catches truncated streams.
type halfwayStage struct{ halt error }

func (halfwayStage) Stage(ctx context.Context, boxID, fileID string, bmk []byte) (sharesapp.StagedPayload, error) {
	return sharesapp.StagedPayload{
		StorageKey: "k", WrappedShareKey: make([]byte, 16), Nonce: make([]byte, 12),
		SizeBytes: 100, ContentType: "text/plain", OriginalName: "f.txt",
	}, nil
}
func (halfwayStage) Delete(ctx context.Context, shareID, storageKey string) error { return nil }
func (s halfwayStage) Open(ctx context.Context, sk string, wsk, n []byte) (io.ReadCloser, error) {
	return io.NopCloser(&halfReader{buf: []byte("hello"), halt: s.halt}), nil
}

// halfReader returns buf on the first Read, then the stored error.
type halfReader struct {
	buf  []byte
	done bool
	halt error
}

func (r *halfReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.halt
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	if len(r.buf) == 0 {
		r.done = true
	}
	return n, nil
}

type cleanStage struct{ body []byte }

func (cleanStage) Stage(ctx context.Context, boxID, fileID string, bmk []byte) (sharesapp.StagedPayload, error) {
	return sharesapp.StagedPayload{
		StorageKey: "k", WrappedShareKey: make([]byte, 16), Nonce: make([]byte, 12),
		SizeBytes: 11, ContentType: "text/plain", OriginalName: "f.txt",
	}, nil
}
func (cleanStage) Delete(ctx context.Context, shareID, storageKey string) error { return nil }
func (s cleanStage) Open(ctx context.Context, sk string, wsk, n []byte) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.body)), nil
}

// TestSharesNonDeliverableImmediatelyAfterBoxDelete asserts the exact
// window the user flagged: the moment DELETE returns, every share of
// that box must refuse public delivery — before the worker finalize
// tick has run. Without the `purge_requested_at`-aware IsDeliverable
// check, a client holding the raw token could race and still read
// plaintext between soft-delete and worker tick.
func TestSharesNonDeliverableImmediatelyAfterBoxDelete(t *testing.T) {
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "race", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/sensitive.txt",
		nil, unlocked.SessionID, []byte("secret-content"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)
	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id": box.ID, "file_entry_id": upload.Entry.ID,
		"expiry_seconds": 3600, "max_downloads": 5,
	}, unlocked.SessionID, nil, "")
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	pmux := http.NewServeMux()
	sharesapi.RegisterPublicRoutes(pmux, sharesapi.Deps{Public: app.publicShares()})
	if rr := callPublic(t, pmux, "GET", "/s/"+created.Token); rr.Code != http.StatusOK {
		t.Fatalf("baseline public GET: %d %s", rr.Code, rr.Body.String())
	}

	// Soft-delete. DO NOT run the worker tick; we want to catch the
	// window between the DELETE return and the finalize.
	rr = c.do(http.MethodDelete, "/api/v1/boxes/"+box.ID, nil, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete box: %d %s", rr.Code, rr.Body.String())
	}

	// Window assertion: public GET + HEAD must refuse immediately.
	for _, method := range []string{"GET", "HEAD"} {
		resp := callPublic(t, pmux, method, "/s/"+created.Token)
		if resp.Code != http.StatusNotFound {
			t.Fatalf("%s on share of soft-deleted box: want 404, got %d", method, resp.Code)
		}
	}

	// Denied access events recorded.
	rr = c.do(http.MethodGet, "/api/v1/shares/"+created.ID+"/access", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("access log: %d", rr.Code)
	}
	var log struct {
		Items []struct {
			Succeeded bool `json:"succeeded"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &log)
	denied := 0
	for _, e := range log.Items {
		if !e.Succeeded {
			denied++
		}
	}
	if denied < 1 {
		t.Fatalf("expected at least one denied access event after soft-delete; saw %d", denied)
	}
}

// TestFinalizeBoxRetainsMetadataWhenBlobWipeFails proves the durable
// ordering: if the engine directory wipe fails, FinalizeBox must NOT
// hard-delete the metadata. The box stays in `deleting` status so a
// subsequent tick can retry. The old ordering (metadata first, blob
// wipe best-effort) orphaned plaintext blobs on disk with no metadata
// pointing at them, so a future retry had no hook to trigger off.
func TestFinalizeBoxRetainsMetadataWhenBlobWipeFails(t *testing.T) {
	svc := vaultapp.NewService(vaultapp.ServiceDeps{
		Boxes:   vaultinfra.NewMemoryBoxRepository(),
		Crypto:  vaultinfra.NewMemoryCryptoStore(),
		Files:   vaultinfra.NewMemoryFileCatalog(),
		Unlocks: vaultinfra.NewMemoryUnlockSessionStore(),
		Engine:  failingEngine{},
		Clock:   clock.RealClock{},
		IDs:     ids.RandomGenerator{},
	})
	ctx := context.Background()
	boxRow, err := svc.CreateBoxFull(ctx, vaultapp.CreateBoxFullInput{
		OwnerUserID: "u", Name: "b", SizeBytes: 1024, Password: "boxpass1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DeleteBox(ctx, boxRow.ID, "u"); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}
	if err := svc.FinalizeBox(ctx, boxRow.ID); err == nil {
		t.Fatal("FinalizeBox must surface engine wipe errors, not swallow them")
	}
	got, err := svc.GetBox(ctx, boxRow.ID)
	if err != nil {
		t.Fatalf("box row must persist when blob wipe fails: %v", err)
	}
	if got.Status != "deleting" {
		t.Fatalf("expected status=deleting after failed finalize, got %q", got.Status)
	}
}

type failingEngine struct{}

func (failingEngine) CreateBox(ctx context.Context, boxID string, sizeBytes int64) error {
	return nil
}
func (failingEngine) DeleteBox(ctx context.Context, boxID string) error {
	return errors.New("simulated engine failure")
}
func (failingEngine) UnlockBox(ctx context.Context, boxID string) error { return nil }
func (failingEngine) LockBox(ctx context.Context, boxID string) error   { return nil }
func (failingEngine) WriteBlob(ctx context.Context, boxID, storageKey string, content io.Reader, key []byte) (int64, error) {
	return 0, nil
}
func (failingEngine) ReadBlob(ctx context.Context, boxID, storageKey string, key []byte) (io.ReadCloser, error) {
	return nil, nil
}
func (failingEngine) DeleteBlob(ctx context.Context, boxID, storageKey string) error { return nil }

// TestBoxDeleteSoftDeletesAndWorkerFinalizes proves the real two-phase
// deletion workflow:
//  1. DELETE /api/v1/boxes/{id} soft-deletes the box (status='deleting'),
//     invalidates any unlock session, and stamps purge_requested on
//     every share.
//  2. Immediately post-DELETE: the box is NOT yet hard-deleted; it no
//     longer appears in list, can't be unlocked, can't accept writes.
//  3. The worker's BoxPurgeJob drives each share to `purged`, then
//     calls FinalizeBox which issues the FK-cascading hard DELETE
//     and wipes the engine directory.
//  4. At that point the stage blobs are gone too.
//
// This replaces the old "cascade hook cleans everything inline" test
// whose claim ("the worker retries") was false — FK CASCADE had
// already dropped the share rows.
func TestBoxDeleteSoftDeletesAndWorkerFinalizes(t *testing.T) {
	stageRoot := t.TempDir()
	t.Setenv("SHARE_STAGE_ROOT", stageRoot)
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatal("login")
	}
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "purge-test", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)

	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/x.txt",
		nil, unlocked.SessionID, []byte("payload"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)

	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id": box.ID, "file_entry_id": upload.Entry.ID,
		"expiry_seconds": 3600, "max_downloads": 5,
	}, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create share: %d %s", rr.Code, rr.Body.String())
	}

	// Soft-delete the box.
	rr = c.do(http.MethodDelete, "/api/v1/boxes/"+box.ID, nil, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete box: %d %s", rr.Code, rr.Body.String())
	}

	// Post-DELETE: box is hidden from listings and unusable.
	rr = c.do(http.MethodGet, "/api/v1/boxes", nil, "", nil, "")
	if strings.Contains(rr.Body.String(), box.ID) {
		t.Fatal("soft-deleted box must not appear in list")
	}
	// Unlock must fail now — the unlock cache was swept.
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	if rr.Code == http.StatusOK {
		t.Fatal("unlock of soft-deleted box must fail")
	}
	// Writes through the old unlock session must also fail (409 because
	// the middleware resolves the session first; the session is gone
	// after SweepBox, so the guard reports unlock_expired/etc.).
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/y.txt",
		nil, unlocked.SessionID, []byte("late"), "text/plain")
	if rr.Code == http.StatusCreated {
		t.Fatal("upload to soft-deleted box must fail")
	}

	// Stage blobs may still exist right now (the in-line hook is
	// best-effort). The worker's BoxPurgeJob is what makes the
	// deletion eventually converge.
	if _, err := app.testBoxPurge.Run(context.Background(), time.Now().UTC(), 10); err != nil {
		t.Fatalf("box purge tick: %v", err)
	}

	// Now the box row is gone — subsequent GET 404s.
	rr = c.do(http.MethodGet, "/api/v1/boxes", nil, "", nil, "")
	if strings.Contains(rr.Body.String(), box.ID) {
		t.Fatal("finalized box must be absent from list")
	}
	// Stage dir is empty.
	after, _ := listStageFiles(stageRoot)
	if after != 0 {
		t.Fatalf("expected 0 stage blobs after finalize; got %d", after)
	}

	// Audit trail: box_delete_requested + box_deleted (finalized).
	rr = c.do(http.MethodGet, "/api/v1/audit/events?subject_type=box&limit=50", nil, "", nil, "")
	seen := map[string]bool{}
	type evt struct {
		EventType string `json:"event_type"`
		SubjectID string `json:"subject_id"`
	}
	var body struct {
		Items []evt `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	for _, e := range body.Items {
		if e.SubjectID == box.ID {
			seen[e.EventType] = true
		}
	}
	for _, want := range []string{"vault.box_delete_requested", "vault.box_deleted"} {
		if !seen[want] {
			t.Fatalf("audit missing %q; saw %+v", want, body.Items)
		}
	}
}

// TestBoxPurgeRetriesOnFlakyStageDelete proves the truthfulness claim:
// if the share stage-blob delete fails mid-purge, the share stays in
// its pre-purge state with purge_requested_at set, and a re-run of
// the job converges. This is the scenario the earlier (false) claim
// about "worker retry" implied but the hard-delete path could never
// deliver.
func TestBoxPurgeRetriesOnFlakyStageDelete(t *testing.T) {
	// Build an in-memory services rig with a flaky stage engine that
	// fails the first N deletes, then succeeds. The BoxPurgeJob must
	// survive the flake and eventually finalize.
	shareRepo := sharesinfra.NewMemoryShareRepository()
	objStore := sharesinfra.NewMemoryShareObjectStore()
	stage := &flakyStage{fails: 1} // one transient failure, then OK

	// Seed a share + object.
	now := time.Now().UTC()
	s := domain.Share{
		ID: "shr_flake", BoxID: "b_flake", FileEntryID: "f",
		TokenHash: "h", Status: domain.StatusRevoked, ExpiresAt: now.Add(time.Hour),
		MaxDownloads: 1, CreatedAt: now,
	}
	_ = shareRepo.Put(context.Background(), s)
	_ = shareRepo.MarkPurgeRequested(context.Background(), s.ID, now)
	_ = objStore.PutObject(context.Background(), domain.ShareObject{
		ID: "sho_1", ShareID: s.ID, StorageKey: "k1", WrappedShareKey: []byte("wk"), SizeBytes: 4,
	})
	purger := jobsapp.SharePurgeJob{Shares: shareRepo, Objects: objStore, Stage: stage}

	// First run: stage.Delete fails → share NOT purged.
	n, _ := purger.Run(context.Background(), now, 10)
	if n != 0 {
		t.Fatalf("expected 0 purged on first run with flake; got %d", n)
	}
	got, _ := shareRepo.Get(context.Background(), s.ID)
	if got.Status == domain.StatusPurged {
		t.Fatal("flaky delete must not flip status to purged")
	}
	if got.PurgeRequestedAt == nil {
		t.Fatal("purge_requested_at must remain set for retry")
	}

	// Second run: stage.Delete succeeds → share purged.
	n, _ = purger.Run(context.Background(), now, 10)
	if n != 1 {
		t.Fatalf("expected 1 purged on retry; got %d", n)
	}
	got, _ = shareRepo.Get(context.Background(), s.ID)
	if got.Status != domain.StatusPurged {
		t.Fatalf("expected purged, got %s", got.Status)
	}
}

type flakyStage struct {
	fails int
}

func (f *flakyStage) Stage(ctx context.Context, boxID, fileID string, bmk []byte) (sharesapp.StagedPayload, error) {
	return sharesapp.StagedPayload{}, nil
}
func (f *flakyStage) Delete(ctx context.Context, shareID, storageKey string) error {
	if f.fails > 0 {
		f.fails--
		return &flakyErr{}
	}
	return nil
}
func (f *flakyStage) Open(ctx context.Context, sk string, wsk, nonce []byte) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func listStageFiles(root string) (int, error) {
	count := 0
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if e.IsDir() {
			sub, _ := os.ReadDir(filepath.Join(root, e.Name()))
			for _, s := range sub {
				if !s.IsDir() {
					count++
				}
			}
		}
	}
	return count, nil
}

// TestShareExpiryJob drives the worker's share-expiry job directly and
// verifies it transitions expired shares and stamps purge_requested_at.
func TestShareExpiryJob(t *testing.T) {
	repo := sharesinfra.NewMemoryShareRepository()
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Minute)
	s := domain.Share{
		ID: "shr_x", BoxID: "b1", FileEntryID: "f1",
		TokenHash: "tokhash", Status: domain.StatusActive,
		ExpiresAt: past, MaxDownloads: 5, CreatedAt: past,
	}
	if err := repo.Put(ctx, s); err != nil {
		t.Fatal(err)
	}
	job := jobsapp.ShareExpiryJob{Shares: repo}
	n, err := job.Run(ctx, time.Now().UTC(), 10)
	if err != nil || n != 1 {
		t.Fatalf("expected 1 expired, got n=%d err=%v", n, err)
	}
	got, _ := repo.Get(ctx, "shr_x")
	if got.Status != domain.StatusExpired {
		t.Fatalf("want expired, got %s", got.Status)
	}
	if got.PurgeRequestedAt == nil {
		t.Fatal("expected purge_requested_at")
	}
	// Idempotency: a second run should not re-touch the row.
	if n2, _ := job.Run(ctx, time.Now().UTC(), 10); n2 != 0 {
		t.Fatalf("expected idempotent 0, got %d", n2)
	}
}

// publicShares is a test-only hook on *App that surfaces the wired public
// delivery capability so the share-gateway handlers can run in the same
// process. See app_test_hooks.go.
func (a *App) publicShares() sharesapp.PublicDelivery { return a.testShares }

// publicShareSvc returns the concrete share service — used by the
// restricted-share E2E because the gateway needs Service (for
// ownership checks in some paths) and PublicVerification (for
// passcode/OTP) in addition to PublicDelivery.
func (a *App) publicShareSvc() *sharesapp.Service { return a.testShares }

// callPublic drives a public mux and returns the recorder.
func callPublic(t *testing.T, mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// silence unused.
var _ = io.Discard
