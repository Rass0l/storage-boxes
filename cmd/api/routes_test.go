package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Rass0l/storage-boxes/internal/platform/database"
)

func TestCommonRoutes(t *testing.T) {
	mux := http.NewServeMux()
	registerCommonRoutes(mux, &database.Connection{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
