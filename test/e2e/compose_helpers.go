//go:build compose_e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	sharedMu    sync.Mutex
	sharedDir   string
	sharedReady bool
)

// composeDir returns the directory containing docker-compose.yml. Determined
// once relative to the current working dir.
func composeDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cwd, "..", "..", "deployments", "compose")
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
		t.Fatalf("compose dir not found at %s: %v", dir, err)
	}
	return dir
}

// ensureSharedStack brings the compose stack up the first time it's called
// inside a package run. Subsequent calls no-op. TestMain calls down once.
func ensureSharedStack(t *testing.T) {
	t.Helper()
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedReady {
		return
	}
	dir := composeDir(t)
	sharedDir = dir

	// Clean state before bringing up so a previous run's volumes don't leak
	// seed rows into this one.
	_ = runCompose(t, dir, "down", "-v", "--remove-orphans")
	if err := runCompose(t, dir, "up", "-d", "--build"); err != nil {
		t.Fatalf("compose up: %v", err)
	}
	sharedReady = true
}

// teardownSharedStack is called from TestMain; no-op if we never brought it up.
func teardownSharedStack() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if !sharedReady || sharedDir == "" {
		return
	}
	cmd := exec.Command("docker", dockerArgs("down", "-v", "--remove-orphans")...)
	cmd.Dir = sharedDir
	_ = cmd.Run()
	sharedReady = false
}

// dockerArgs builds the full `docker compose [-f …] <args>` argv,
// prepending any `-f` files the COMPOSE_FILES env var carries. The
// Makefile sets COMPOSE_FILES for compose-e2e so pg-direct tests can
// reach Postgres on localhost; unset means base file only (the
// production shape).
func dockerArgs(args ...string) []string {
	out := []string{"compose"}
	if extra := strings.TrimSpace(os.Getenv("COMPOSE_FILES")); extra != "" {
		out = append(out, strings.Fields(extra)...)
	}
	return append(out, args...)
}

func runCompose(t *testing.T, dir string, args ...string) error {
	cmd := exec.Command("docker", dockerArgs(args...)...)
	cmd.Dir = dir
	cmd.Stdout = testWriter{t}
	cmd.Stderr = testWriter{t}
	return cmd.Run()
}

// restartService restarts a compose service in-place (used by the durability
// test). The shared stack state stays "up".
func restartService(t *testing.T, service string) {
	t.Helper()
	if err := runCompose(t, sharedDir, "restart", service); err != nil {
		t.Fatalf("compose restart %s: %v", service, err)
	}
}
