package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicShareRouteExistsOutsideAPIPrefix(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	content := string(b)
	if !strings.Contains(content, "/s/{token}:") {
		t.Fatal("expected public share route in openapi")
	}
	if strings.Contains(content, "/api/v1/s/{token}") {
		t.Fatal("share route must not live under /api/v1")
	}
}
