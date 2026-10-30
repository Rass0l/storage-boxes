package api_test

import (
	"context"
	"encoding/json"
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

// buildAccessRequestGateway returns a service (with the access-request repo
// wired) plus a gateway mux that registers the public request-access /
// request-status endpoints, and the created restricted share token.
func buildAccessRequestGateway(t *testing.T) (*app.Service, *http.ServeMux, string) {
	t.Helper()
	requests := infra.NewMemoryAccessRequestRepository()
	svc := app.NewService(app.Deps{
		Shares:         infra.NewMemoryShareRepository(),
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     infra.NewMemoryRecipientRepository(),
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		AccessRequests: requests,
		Files:          fakeFiles{},
		Stage:          &fakeStage{payload: []byte("hi")},
		Tokens:         infra.RandomTokenService{},
	})
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "u1", BoxID: "b1", FileEntryID: "f1",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"member@example.com"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	mux := http.NewServeMux()
	api.RegisterGatewayRoutes(mux, api.GatewayDeps{
		Deps:           api.Deps{Public: svc, Service: svc},
		Verification:   svc,
		AccessRequests: svc,
	})
	return svc, mux, res.RawToken
}

func TestGatewayRequestAccessSubmitReturnsCoarseStatusOnly(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	body, _ := json.Marshal(map[string]string{"email": "newcomer@example.com", "message": "please"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/request-access", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != app.PublicStatusPending {
		t.Fatalf("want pending status, got %v", got["status"])
	}
	// The public response must carry ONLY a coarse status — no ids, owner
	// data, decision metadata, or file metadata.
	if len(got) != 1 {
		t.Fatalf("public submit response must contain only {status}, got %v", got)
	}
}

func TestGatewayRequestAccessSubmitRejectsMissingEmail(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/request-access", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestGatewayRequestStatusCoarse(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	// Existing recipient → approved (verify now).
	rr := doStatus(t, mux, token, "member@example.com")
	if rr["status"] != app.PublicStatusApproved {
		t.Fatalf("recipient should map to approved, got %v", rr["status"])
	}
	// Unknown email → none.
	rr = doStatus(t, mux, token, "ghost@example.com")
	if rr["status"] != app.PublicStatusNone {
		t.Fatalf("unknown email should map to none, got %v", rr["status"])
	}
	if len(rr) != 1 {
		t.Fatalf("status response must contain only {status}, got %v", rr)
	}
}

func TestGatewayRequestStatusAfterSubmitIsPending(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	body, _ := json.Marshal(map[string]string{"email": "waiting@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+token+"/request-access", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	mux.ServeHTTP(httptest.NewRecorder(), req)
	got := doStatus(t, mux, token, "waiting@example.com")
	if got["status"] != app.PublicStatusPending {
		t.Fatalf("want pending, got %v", got["status"])
	}
}

func TestGatewayRequestAccessPageRenders(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/s/"+token+"/request-access", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "/request-access") {
		t.Fatalf("request-access page should post to the request-access endpoint")
	}
}

func TestGatewayVerifyPageLinksToRequestAccess(t *testing.T) {
	_, mux, token := buildAccessRequestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/s/"+token+"/verify", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "/s/"+token+"/request-access") {
		t.Fatalf("verify page should link to request-access; body=%s", rr.Body.String())
	}
}

func doStatus(t *testing.T, mux *http.ServeMux, token, email string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/s/"+token+"/request-status?email="+email, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}
