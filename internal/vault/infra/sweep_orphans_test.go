package infra

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSweepOrphansDropsUnknownBlobsKeepsKnown(t *testing.T) {
	engine := NewEncryptedFSBoxEngine(t.TempDir())
	boxID := "box_sweep"
	ctx := context.Background()
	if err := engine.CreateBox(ctx, boxID, 0); err != nil {
		t.Fatalf("create: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for _, id := range []string{"keep1", "keep2", "orphan1", "orphan2"} {
		if _, err := engine.WriteBlob(ctx, boxID, id, bytes.NewReader([]byte(id)), key); err != nil {
			t.Fatalf("write %s: %v", id, err)
		}
	}
	// Drop a stale `.tmp` file that SweepOrphans must ignore.
	tmpPath := filepath.Join(engine.Root, boxID, "in-flight.tmp")
	if err := os.WriteFile(tmpPath, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := engine.SweepOrphans(ctx, boxID, map[string]bool{"keep1": true, "keep2": true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 2 {
		t.Fatalf("expected 2 orphans removed, got %d", removed)
	}

	remaining, err := os.ReadDir(filepath.Join(engine.Root, boxID))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range remaining {
		got[d.Name()] = true
	}
	if !got["keep1"] || !got["keep2"] {
		t.Fatalf("known blobs were wiped: %v", got)
	}
	if got["orphan1"] || got["orphan2"] {
		t.Fatalf("orphans survived: %v", got)
	}
	if !got["in-flight.tmp"] {
		t.Fatalf("in-flight .tmp file was wiped (would race concurrent uploads): %v", got)
	}
}
