package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// locate walks up from the package's CWD until it finds `relative` so
// tests work whether invoked from the repo root or the package dir.
func locate(t *testing.T, relative string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		path := filepath.Join(dir, relative)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate %s from %s", relative, dir)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
