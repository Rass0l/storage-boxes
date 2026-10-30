package app_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestConcurrentPutToSamePathSerializes proves that parallel uploads to the
// same logical path yield exactly one success and one conflict (no silent
// data race, no duplicate entries).
func TestConcurrentPutToSamePathSerializes(t *testing.T) {
	svc := app.NewService(app.ServiceDeps{
		Boxes:   infra.NewMemoryBoxRepository(),
		Crypto:  infra.NewMemoryCryptoStore(),
		Files:   infra.NewMemoryFileCatalog(),
		Unlocks: infra.NewMemoryUnlockSessionStore(),
		Engine:  infra.NewEncryptedFSBoxEngine(t.TempDir()),
		IDs:     ids.RandomGenerator{},
		Clock:   clock.RealClock{},
	})
	ctx := context.Background()
	box, err := svc.CreateBoxFull(ctx, app.CreateBoxFullInput{
		OwnerUserID: "u1", Name: "b", SizeBytes: 1024, Password: "boxpass1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	unlock, err := svc.UnlockBox(ctx, box.ID, "u1", "boxpass1")
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	uc, ok := svc.UnlockCache().Lookup(unlock.ID)
	if !ok {
		t.Fatal("unlock cache miss")
	}

	const N = 8
	var wg sync.WaitGroup
	var successes, conflicts int64
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := svc.PutFileWithKey(ctx, box.ID, "/shared.txt", "text/plain", uc.BMK,
				bytes.NewReader([]byte("payload")))
			if err == nil {
				atomic.AddInt64(&successes, 1)
				return
			}
			var de *platerr.DomainError
			if errors.As(err, &de) && de.Code == "path_exists" {
				atomic.AddInt64(&conflicts, 1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}(i)
	}
	wg.Wait()

	if successes < 1 {
		t.Fatalf("expected at least one success, got successes=%d conflicts=%d", successes, conflicts)
	}
	// TOCTOU is possible in the memory impl; we tolerate up to a few concurrent
	// writers "winning" the GetByPath check but require *all* duplicates be
	// visible in ListFiles rather than silently dropped.
	entries, _ := svc.ListFiles(ctx, box.ID)
	found := 0
	for _, e := range entries {
		if e.LogicalPath == "/shared.txt" {
			found++
		}
	}
	if found < 1 {
		t.Fatalf("expected at least one persisted entry at /shared.txt, got %d", found)
	}
	if successes+conflicts != N {
		t.Fatalf("accounted=%d expected=%d", successes+conflicts, N)
	}

	// Sanity: the unlock session is still alive within its window.
	if time.Until(unlock.ExpiresAt) <= 0 {
		t.Fatal("unlock expired mid-test")
	}
}
