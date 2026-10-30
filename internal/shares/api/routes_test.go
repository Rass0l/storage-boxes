package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStubListRoute exercises the zero-deps registration path so tests that
// don't wire a real service (older harnesses) continue to return 200 on
// /api/v1/shares.
func TestStubListRoute(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/shares", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestPublicStubRoute exercises RegisterPublicRoutes without a delivery impl
// — it should report 503 so callers see a clear signal that the runtime
// isn't wired, rather than a placeholder 200.
func TestPublicStubRoute(t *testing.T) {
	mux := http.NewServeMux()
	RegisterPublicRoutes(mux, Deps{})
	req := httptest.NewRequest(http.MethodGet, "/s/anything", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}
