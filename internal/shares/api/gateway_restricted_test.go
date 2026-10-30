package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/api"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// fakeStage is a minimal StageEngine that can both stage (for create) and
// open (for delivery) with a single in-memory byte buffer.
type fakeStage struct {
	payload []byte
}

func (f *fakeStage) Stage(_ context.Context, _ string, _ string, _ []byte) (app.StagedPayload, error) {
	return app.StagedPayload{
		StorageKey:      "sk1",
		WrappedShareKey: []byte("wskwskwskwskwskw"),
		Nonce:           []byte("nonce-nonce-"),
		SizeBytes:       int64(len(f.payload)),
		ContentType:     "text/plain",
		OriginalName:    "file.txt",
	}, nil
}
func (f *fakeStage) Delete(_ context.Context, _, _ string) error { return nil }
func (f *fakeStage) Open(_ context.Context, _ string, _, _ []byte) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(f.payload))), nil
}

type fakeFiles struct{}

func (fakeFiles) LookupFile(_ context.Context, _ string, _ string) (app.FileMeta, error) {
	return app.FileMeta{Name: "file.txt", ContentType: "text/plain", SizeBytes: 5}, nil
}

func buildGatewayService(t *testing.T, payload []byte) (*app.Service, string, []domain.Recipient, map[string]string) {
	t.Helper()
	stage := &fakeStage{payload: payload}
	svc := app.NewService(app.Deps{
		Shares:     infra.NewMemoryShareRepository(),
		Objects:    infra.NewMemoryShareObjectStore(),
		AccessLog:  infra.NewMemoryAccessRecorder(),
		Recipients: infra.NewMemoryRecipientRepository(),
		Challenges: infra.NewMemoryChallengeRepository(),
		Claims:     infra.NewMemoryClaimRepository(),
		Files:      fakeFiles{},
		Stage:      stage,
		Tokens:     infra.RandomTokenService{},
	})
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "u1", BoxID: "b1", FileEntryID: "f1",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy: app.SharePolicy{
			AccessMode:      domain.AccessModeRestricted,
			RecipientEmails: []string{"dest@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return svc, res.RawToken, res.Recipients, res.RecipientPasscodes
}

// TestGatewayRedirectsRestrictedDownloadWithoutClaim proves GET /s/{token}
// on a restricted share with no cookie 303s to the verify page.
func TestGatewayRedirectsRestrictedDownloadWithoutClaim(t *testing.T) {
	svc, token, _, _ := buildGatewayService(t, []byte("hello"))
	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})
	req := httptest.NewRequest(http.MethodGet, "/s/"+token, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.HasSuffix(rr.Header().Get("Location"), "/verify") {
		t.Fatalf("redirect target: %s", rr.Header().Get("Location"))
	}
}

// TestGatewayVerifyIssuesCookieAndDelivers exercises POST /s/{token}/verify
// with a correct passcode + subsequent GET /s/{token} using the returned
// cookie.
func TestGatewayVerifyIssuesCookieAndDelivers(t *testing.T) {
	svc, token, recs, passcodes := buildGatewayService(t, []byte("payload-bytes"))
	rec := recs[0]
	passcode := passcodes[rec.ID]

	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})

	// POST verify with JSON to avoid redirect; expect cookie back.
	body, _ := json.Marshal(map[string]string{"email": rec.Email, "passcode": passcode})
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/verify", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Cookie must be set.
	setCookie := rr.Result().Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, api.ShareClaimCookieName+"=") {
		t.Fatalf("missing claim cookie; headers=%v", rr.Result().Header)
	}
	// Follow with GET and the cookie.
	getReq := httptest.NewRequest(http.MethodGet, "/s/"+token, nil)
	for _, c := range rr.Result().Cookies() {
		getReq.AddCookie(c)
	}
	getRR := httptest.NewRecorder()
	mux.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("download: want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	if getRR.Body.String() != "payload-bytes" {
		t.Fatalf("download body=%q", getRR.Body.String())
	}
}

// TestGatewayRecordsStaleCookieDenial exercises the "share never
// opens" branch: recipient has a claim cookie, the claim is then
// revoked, they try to download — the GET gets redirected to /verify,
// but BEFORE the redirect the gateway writes an attributed
// share_access_events row with reason=claim_revoked so the recipient
// timeline reflects the attempt.
//
// No-cookie GETs stay silent by design (they are the normal "please
// verify" path and would otherwise fill the access log with every
// browser navigation).
func TestGatewayRecordsStaleCookieDenial(t *testing.T) {
	svc, token, recs, passcodes := buildGatewayService(t, []byte("p"))
	rec := recs[0]

	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})

	// Verify → get cookie.
	body, _ := json.Marshal(map[string]string{"email": rec.Email, "passcode": passcodes[rec.ID]})
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/verify", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: %d", rr.Code)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == api.ShareClaimCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no claim cookie")
	}

	// Revoke the recipient while the cookie is still held by the
	// caller — the classic "stale cookie" case.
	if err := svc.RevokeRecipient(context.Background(), "u1", recs[0].ShareID, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Download attempt — must 303 (redirect to /verify) with NO body.
	req = httptest.NewRequest(http.MethodGet, "/s/"+token, nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}

	// The denial row must exist in share_access_events, attributed
	// to the revoked recipient, with reason=claim_revoked.
	events, err := svc.ListAccess(context.Background(), "u1", recs[0].ShareID, 50)
	if err != nil {
		t.Fatalf("list access: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Succeeded {
			continue
		}
		if e.RecipientID != rec.ID {
			continue
		}
		if reason, _ := e.Metadata["reason"].(string); reason == "claim_revoked" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected attributed claim_revoked denial row; got %+v", events)
	}
}

// TestGatewayNoCookieRecordsDenial locks the contract that every
// restricted GET — including the first navigation with no cookie —
// writes a share_access_events row, so the operator's /access view
// sees the full pattern of turned-away attempts. The no-cookie case
// carries reason=claim_required and no recipient_id (we can't
// attribute an attempt that never presented a cookie).
//
// This flipped from the previous "silent please-verify-first" policy;
// leaving it silent hid real denials (probing, bad tokens) from the
// audit trail.
func TestGatewayNoCookieRecordsDenial(t *testing.T) {
	svc, token, recs, _ := buildGatewayService(t, []byte("p"))
	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})
	req := httptest.NewRequest(http.MethodGet, "/s/"+token, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}
	events, _ := svc.ListAccess(context.Background(), "u1", recs[0].ShareID, 50)
	if len(events) != 1 {
		t.Fatalf("no-cookie GET must record exactly one denial; got %d", len(events))
	}
	ev := events[0]
	if ev.Succeeded {
		t.Fatal("no-cookie GET must be succeeded=false")
	}
	if ev.RecipientID != "" {
		t.Fatalf("no-cookie GET must not attribute a recipient; got %q", ev.RecipientID)
	}
	if reason, _ := ev.Metadata["reason"].(string); reason != "claim_required" {
		t.Fatalf("no-cookie GET reason: got %q, want claim_required", reason)
	}
}

// TestGatewayHeadNoCookieStaysSilent enforces RFC 9110 § 9.3.2 — HEAD
// must not have side effects. A probe without a claim cookie
// returns 401 WITHOUT writing an access row. GET is where denials
// land.
func TestGatewayHeadNoCookieStaysSilent(t *testing.T) {
	svc, token, recs, _ := buildGatewayService(t, []byte("p"))
	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})
	req := httptest.NewRequest(http.MethodHead, "/s/"+token, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	events, _ := svc.ListAccess(context.Background(), "u1", recs[0].ShareID, 50)
	if len(events) != 0 {
		t.Fatalf("HEAD must not write access rows; got %d", len(events))
	}
}

// TestGatewayWrongPasscodeReturnsError ensures failure paths surface a
// domain error shape rather than the success response.
func TestGatewayWrongPasscodeReturnsError(t *testing.T) {
	svc, token, recs, _ := buildGatewayService(t, []byte("x"))
	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:         api.Deps{Public: svc, Service: svc},
		Verification: svc,
	})
	body, _ := json.Marshal(map[string]string{"email": recs[0].Email, "passcode": "ZZZZZZZZ"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/verify", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 on wrong passcode, got %d", rr.Code)
	}
}

// TestClaimCookieSecureIsEnvironmentAware proves the claim cookie's Secure
// attribute follows SecureCookies: set in production HTTPS, off for local
// HTTP development so the cookie is actually stored over http://localhost.
// HttpOnly is always present.
func TestClaimCookieSecureIsEnvironmentAware(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
	}{{"prod_https", true}, {"local_http", false}} {
		t.Run(tc.name, func(t *testing.T) {
			svc, token, recs, passcodes := buildGatewayService(t, []byte("p"))
			rec := recs[0]
			mux := http.NewServeMux()
			api.RegisterGatewayRoutes(mux, api.GatewayDeps{
				Deps:          api.Deps{Public: svc, Service: svc},
				Verification:  svc,
				SecureCookies: tc.secure,
			})
			body, _ := json.Marshal(map[string]string{"email": rec.Email, "passcode": passcodes[rec.ID]})
			req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/verify", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("verify: %d", rr.Code)
			}
			var claim *http.Cookie
			for _, c := range rr.Result().Cookies() {
				if c.Name == api.ShareClaimCookieName {
					claim = c
				}
			}
			if claim == nil {
				t.Fatal("no claim cookie set")
			}
			if !claim.HttpOnly {
				t.Fatal("claim cookie must always be HttpOnly")
			}
			if claim.Secure != tc.secure {
				t.Fatalf("Secure=%v, want %v", claim.Secure, tc.secure)
			}
			if claim.SameSite != http.SameSiteStrictMode {
				t.Fatalf("claim cookie SameSite=%v, want Strict", claim.SameSite)
			}
		})
	}
}
