package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestADRFilesContainDecisionSections(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "docs", "adr", "ADR-001-modular-monolith-boundaries.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-002-metadata-visibility-without-unlock.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-003-go-dependency-vendoring-policy.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-004-api-versioning-policy.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-005-audit-append-only-policy.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-006-share-staging-model.md"),
		filepath.Join("..", "..", "docs", "adr", "ADR-007-audit-outbox-dispatch.md"),
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read ADR %s: %v", file, err)
		}
		content := string(b)
		for _, snippet := range []string{"## Status", "## Context", "## Decision"} {
			if !strings.Contains(content, snippet) {
				t.Fatalf("%s missing section %q", file, snippet)
			}
		}
	}
}
