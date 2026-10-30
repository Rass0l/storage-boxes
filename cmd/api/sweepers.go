package main

import (
	"context"
	"time"

	identityinfra "github.com/Rass0l/storage-boxes/internal/identity/infra"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
)

// startSweepers runs the process-local expiry sweepers — the in-memory
// session store (memory mode only) and the in-process BMK cache.
// DB-level sweeps for sessions and unlock sessions live in cmd/worker so
// they keep progressing even when this API process is down.
func startSweepers(
	interval time.Duration,
	memSessions *identityinfra.MemorySessionStore,
	unlockCache *vaultapp.UnlockCache,
) context.CancelFunc {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				if memSessions != nil {
					memSessions.Sweep(now)
				}
				if unlockCache != nil {
					unlockCache.Sweep(now)
				}
			}
		}
	}()
	return cancel
}
