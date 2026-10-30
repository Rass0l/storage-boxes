package database

import (
	"context"
	"testing"
)

func TestParseDSN(t *testing.T) {
	meta, err := ParseDSN("postgres://postgres:postgres@localhost:5432/app?sslmode=disable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Port != "5432" {
		t.Fatalf("expected default port, got %s", meta.Port)
	}
	if meta.Database != "app" {
		t.Fatalf("expected database app, got %s", meta.Database)
	}
}

// Memory mode must be reachable without any Postgres running.
func TestOpenMemorySentinel(t *testing.T) {
	conn, err := Open(MemoryDSN)
	if err != nil {
		t.Fatalf("open mem: %v", err)
	}
	if !conn.IsMemory() {
		t.Fatal("expected memory connection")
	}
	if err := conn.PingContext(context.Background()); err != nil {
		t.Fatalf("ping mem: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close mem: %v", err)
	}
}
