package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditinfra "github.com/Rass0l/storage-boxes/internal/audit/infra"
	identityinfra "github.com/Rass0l/storage-boxes/internal/identity/infra"
	jobsapp "github.com/Rass0l/storage-boxes/internal/jobs/app"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/config"
	"github.com/Rass0l/storage-boxes/internal/platform/database"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/platform/observability"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

type jobStats struct {
	lastRun     atomic.Pointer[time.Time]
	sessionRows atomic.Int64
	unlockRows  atomic.Int64
	shareExpiry atomic.Int64
	sharePurge  atomic.Int64
	boxPurge    atomic.Int64
	outboxSent  atomic.Int64
	claimExpiry atomic.Int64
	reconciled  atomic.Int64
	accessReqs  atomic.Int64
}

func main() {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	db, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	logger := observability.NewStdLogger("worker")
	stats := &jobStats{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if pool := db.Pool(); pool != nil {
		sessions := identityinfra.NewPGSessionStore(pool, identityinfra.PGSessionOptions{
			IdleTimeout: 24 * time.Hour, AbsoluteTimeout: 7 * 24 * time.Hour, Clock: clock.RealClock{},
		})
		unlocks := vaultinfra.NewPGUnlockSessionStore(pool)
		shareRepo := sharesinfra.NewPGShareRepository(pool)
		objStore := sharesinfra.NewPGShareObjectStore(pool)
		stageRoot := envOr("SHARE_STAGE_ROOT", "./.share-stage")
		stage := sharesinfra.NewShareStageEngine(stageRoot, deriveMasterKey(os.Getenv("SERVER_MASTER_KEY")), nil)
		auditSvc := auditapp.NewService(auditapp.Deps{
			Repo:    auditinfra.NewPGAuditRepository(pool),
			Outbox:  auditinfra.NewPGOutboxRepository(pool),
			Signals: auditinfra.NewPGRiskSignalRepository(pool),
			Clock:   clock.RealClock{},
			IDs:     ids.RandomGenerator{},
		})
		shareExpiry := jobsapp.ShareExpiryJob{Shares: shareRepo, Audit: auditSvc}
		sharePurge := jobsapp.SharePurgeJob{Shares: shareRepo, Objects: objStore, Stage: stage, Audit: auditSvc}
		outboxJob := jobsapp.OutboxDispatchJob{Outbox: auditinfra.NewPGOutboxRepository(pool)}
		claimRepo := sharesinfra.NewPGClaimRepository(pool)
		claimExpiry := jobsapp.ClaimExpiryJob{Claims: claimRepo, Audit: auditSvc}
		reconciler := jobsapp.ShareReconciliationJob{Shares: shareRepo, Claims: claimRepo, Audit: auditSvc}
		accessReqRepo := sharesinfra.NewPGAccessRequestRepository(pool)
		accessReqCleanup := jobsapp.AccessRequestCleanupJob{Requests: accessReqRepo, Audit: auditSvc}

		// BoxPurgeJob drives soft-deleted boxes to hard-delete once every
		// share has reached `purged`. A minimal vault.Service (engine +
		// repos, no HTTP path) supplies FinalizeBox.
		boxRepo := vaultinfra.NewPGBoxRepository(pool)
		vaultFinalizer := vaultapp.NewService(vaultapp.ServiceDeps{
			Boxes:   boxRepo,
			Crypto:  vaultinfra.NewPGCryptoStore(pool),
			Files:   vaultinfra.NewPGFileCatalog(pool),
			Unlocks: vaultinfra.NewPGUnlockSessionStore(pool),
			Engine:  vaultinfra.NewEncryptedFSBoxEngine(envOr("BOX_STORAGE_ROOT", "./.box-storage")),
			Clock:   clock.RealClock{},
			IDs:     ids.RandomGenerator{},
		})
		boxPurge := jobsapp.BoxPurgeJob{
			Boxes:  workerBoxFinalizer{svc: vaultFinalizer},
			Shares: shareRepo,
			Purger: sharePurge,
			Audit:  auditSvc,
		}
		go runSweepers(ctx, logger, stats, sessions, unlocks, shareExpiry, sharePurge, boxPurge, outboxJob, claimExpiry, reconciler, accessReqCleanup)
	}

	mux := http.NewServeMux()
	registerWorkerRoutes(mux, db, stats)

	srv := &http.Server{Addr: cfg.WorkerAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Infof("worker listening on %s", cfg.WorkerAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("worker stopped: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	cancel()
	shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	_ = srv.Shutdown(shutdownCtx)
}

// runSweepers periodically cleans expired auth + unlock sessions, expires
// shares that have passed their TTL, purges revoked/expired shares (by
// deleting staged blobs + rows), and dispatches the domain outbox. Each
// job is idempotent so worker restarts are safe.
// workerBoxFinalizer adapts *vaultapp.Service to jobs.BoxFinalizer so
// BoxPurgeJob doesn't import the vault package's domain.Box type.
type workerBoxFinalizer struct{ svc *vaultapp.Service }

func (a workerBoxFinalizer) ListPurgeCandidateBoxes(ctx context.Context, limit int) ([]jobsapp.BoxRef, error) {
	boxes, err := a.svc.ListPurgeCandidateBoxes(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]jobsapp.BoxRef, 0, len(boxes))
	for _, b := range boxes {
		out = append(out, jobsapp.BoxRef{ID: b.ID, OwnerID: b.OwnerUserID})
	}
	return out, nil
}

func (a workerBoxFinalizer) FinalizeBox(ctx context.Context, boxID string) error {
	return a.svc.FinalizeBox(ctx, boxID)
}

func runSweepers(ctx context.Context, log *observability.StdLogger, stats *jobStats,
	sessions *identityinfra.PGSessionStore, unlocks *vaultinfra.PGUnlockSessionStore,
	shareExpiry jobsapp.ShareExpiryJob, sharePurge jobsapp.SharePurgeJob, boxPurge jobsapp.BoxPurgeJob, outbox jobsapp.OutboxDispatchJob,
	claimExpiry jobsapp.ClaimExpiryJob, reconciler jobsapp.ShareReconciliationJob, accessReqCleanup jobsapp.AccessRequestCleanupJob,
) {
	sweep := durationEnv("WORKER_SWEEP_INTERVAL", 5*time.Minute)
	shareInt := durationEnv("WORKER_SHARE_INTERVAL", time.Minute)
	outboxInt := durationEnv("WORKER_OUTBOX_INTERVAL", 15*time.Second)
	reconcileInt := durationEnv("WORKER_RECONCILE_INTERVAL", 15*time.Minute)

	tickSweep := time.NewTicker(sweep)
	tickShare := time.NewTicker(shareInt)
	tickOutbox := time.NewTicker(outboxInt)
	tickReconcile := time.NewTicker(reconcileInt)
	defer tickSweep.Stop()
	defer tickShare.Stop()
	defer tickOutbox.Stop()
	defer tickReconcile.Stop()

	runSweep := func(now time.Time) {
		cctx, c := context.WithTimeout(ctx, 30*time.Second)
		defer c()
		n1, err := sessions.Sweep(cctx, now)
		if err != nil {
			log.Errorf("session sweep: %v", err)
		}
		n2, err := unlocks.Sweep(cctx, now)
		if err != nil {
			log.Errorf("unlock sweep: %v", err)
		}
		t := now
		stats.lastRun.Store(&t)
		stats.sessionRows.Add(n1)
		stats.unlockRows.Add(n2)
	}
	runShare := func(now time.Time) {
		cctx, c := context.WithTimeout(ctx, 30*time.Second)
		defer c()
		n, err := shareExpiry.Run(cctx, now, 100)
		if err != nil {
			log.Errorf("share expiry: %v", err)
		}
		stats.shareExpiry.Add(int64(n))
		n2, err := sharePurge.Run(cctx, now, 100)
		if err != nil {
			log.Errorf("share purge: %v", err)
		}
		stats.sharePurge.Add(int64(n2))
		// Box finalizer runs on the same tick as share purge so a
		// freshly-purged share promptly unblocks its parent box.
		n3, err := boxPurge.Run(cctx, now, 50)
		if err != nil {
			log.Errorf("box purge: %v", err)
		}
		stats.boxPurge.Add(int64(n3))
		// ClaimExpiryJob runs alongside share sweep so recipient claim
		// cookies stop working the moment their TTL elapses.
		n4, err := claimExpiry.Run(cctx, now, 200)
		if err != nil {
			log.Errorf("claim expiry: %v", err)
		}
		stats.claimExpiry.Add(int64(n4))
		// AccessRequestCleanupJob converges stale pending access requests
		// (TTL-expired, tied to dead shares, or already-active recipients).
		// An access request grants nothing, so the regular share tick is
		// sufficient — no boot-before-readiness gate needed.
		n5, err := accessReqCleanup.Run(cctx, now, 200)
		if err != nil {
			log.Errorf("access request cleanup: %v", err)
		}
		stats.accessReqs.Add(int64(n5))
	}
	runReconcile := func(now time.Time) {
		cctx, c := context.WithTimeout(ctx, 60*time.Second)
		defer c()
		n, err := reconciler.Run(cctx, now, 500)
		if err != nil {
			log.Errorf("share reconciliation: %v", err)
		}
		stats.reconciled.Add(int64(n))
	}
	runOutbox := func(now time.Time) {
		cctx, c := context.WithTimeout(ctx, 15*time.Second)
		defer c()
		n, err := outbox.Run(cctx, now, 50)
		if err != nil {
			log.Errorf("outbox dispatch: %v", err)
		}
		stats.outboxSent.Add(int64(n))
	}

	runSweep(time.Now().UTC())
	runShare(time.Now().UTC())
	runOutbox(time.Now().UTC())
	// Reconciliation runs once on boot to clear any inconsistent state
	// left by a restore or a previous-restart crash before API/gateway
	// readiness signals converge.
	runReconcile(time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tickSweep.C:
			runSweep(t.UTC())
		case t := <-tickShare.C:
			runShare(t.UTC())
		case t := <-tickOutbox.C:
			runOutbox(t.UTC())
		case t := <-tickReconcile.C:
			runReconcile(t.UTC())
		}
	}
}

func registerWorkerRoutes(mux *http.ServeMux, db *database.Connection, stats *jobStats) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","runtime":"worker"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready","reason":"database_unreachable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready","runtime":"worker"}`))
	})
	mux.HandleFunc("GET /api/v1/worker/sweep-stats", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		last := stats.lastRun.Load()
		when := ""
		if last != nil {
			when = last.Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"last_run":%q,"session_rows_removed":%d,"unlock_rows_removed":%d,"shares_expired":%d,"shares_purged":%d,"boxes_purged":%d,"outbox_dispatched":%d,"claims_expired":%d,"reconciled":%d,"access_requests_cleaned":%d}`,
			when, stats.sessionRows.Load(), stats.unlockRows.Load(),
			stats.shareExpiry.Load(), stats.sharePurge.Load(), stats.boxPurge.Load(), stats.outboxSent.Load(),
			stats.claimExpiry.Load(), stats.reconciled.Load(), stats.accessReqs.Load())
	})
	mux.HandleFunc("GET /api/v1/worker/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jobs":["session_sweep","unlock_sweep","share_expiry","share_purge","box_purge","outbox_dispatch","claim_expiry","share_reconciliation","access_request_cleanup"]}`)
	})
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func deriveMasterKey(hexKey string) []byte {
	if hexKey == "" {
		return make([]byte, 32)
	}
	if raw, err := hex.DecodeString(hexKey); err == nil && len(raw) >= 32 {
		out := make([]byte, 32)
		copy(out, raw[:32])
		return out
	}
	sum := sha256.Sum256([]byte(hexKey))
	return sum[:]
}

// silence the unused import in memory-mode builds.
var _ = config.IsProductionLike
