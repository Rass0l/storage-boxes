package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAPIExamplesExist(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "api", "openapi", "examples", "login-success.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "box-list-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "file-tree-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "share-create-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "share-create-restricted-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "share-list-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "share-detail-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "share-access-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "audit-event-page.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "access-request-list-response.json"),
		filepath.Join("..", "..", "api", "openapi", "examples", "access-request-approve-response.json"),
	}
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("missing OpenAPI example %s: %v", file, err)
		}
	}
}
