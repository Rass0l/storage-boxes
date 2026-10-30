package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditinfra "github.com/Rass0l/storage-boxes/internal/audit/infra"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/config"
	"github.com/Rass0l/storage-boxes/internal/platform/database"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/platform/observability"
	sharesapi "github.com/Rass0l/storage-boxes/internal/shares/api"
	sharesapp "github.com/Rass0l/storage-boxes/internal/shares/app"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// share-gateway is the public, unauthenticated face of shares. It never
// issues session cookies, never unlocks vault boxes, and never touches the
// vault engine directly — it only opens staged, per-share-encrypted blobs
// under SHARE_STAGE_ROOT. Compromising it does not compromise vault data.
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

	logger := observability.NewStdLogger("share-gateway")
	mux := http.NewServeMux()
	registerShareGatewayRoutes(mux, db)

	if pool := db.Pool(); pool != nil {
		shareRepo := sharesinfra.NewPGShareRepository(pool)
		objStore := sharesinfra.NewPGShareObjectStore(pool)
		access := sharesinfra.NewPGAccessRecorder(pool)
		recipients := sharesinfra.NewPGRecipientRepository(pool)
		challenges := sharesinfra.NewPGChallengeRepository(pool)
		claims := sharesinfra.NewPGClaimRepository(pool)
		accessReqRepo := sharesinfra.NewPGAccessRequestRepository(pool)
		masterKey := deriveMasterKey(os.Getenv("SERVER_MASTER_KEY"))
		stageRoot := envOr("SHARE_STAGE_ROOT", "./.share-stage")
		// Stage engine only needs to Open here — staging happens in api.
		stage := sharesinfra.NewShareStageEngine(stageRoot, masterKey, nil)
		auditSvc := auditapp.NewService(auditapp.Deps{
			Repo:    auditinfra.NewPGAuditRepository(pool),
			Outbox:  auditinfra.NewPGOutboxRepository(pool),
			Signals: auditinfra.NewPGRiskSignalRepository(pool),
			Clock:   clock.RealClock{},
			IDs:     ids.RandomGenerator{},
		})
		// OTP delivery: production-like environments deliver the code
		// out-of-band via the configured dispatcher (SHARE_OTP_SMTP_*).
		// Local/dev (no dispatcher) surfaces the code in the verify
		// response instead.
		devOTPEcho := !config.IsProductionLike(cfg.AppEnv)
		otpDispatcher := buildOTPDispatcher(cfg)
		shareSvc := sharesapp.NewService(sharesapp.Deps{
			Shares:           shareRepo,
			Objects:          objStore,
			AccessLog:        access,
			Recipients:       recipients,
			Challenges:       challenges,
			Claims:           claims,
			AccessRequests:   accessReqRepo,
			AccessRequestTTL: accessRequestTTL(),
			Stage:            stage,
			Tokens:           sharesinfra.RandomTokenService{},
			Audit:            auditSvc,
			Clock:            clock.RealClock{},
			IDs:              ids.RandomGenerator{},
			OTPDispatcher:    otpDispatcher,
			DevModeOTPEcho:   devOTPEcho,
		})
		sharesapi.RegisterGatewayRoutes(mux, sharesapi.GatewayDeps{
			Deps: sharesapi.Deps{
				Service:        shareSvc,
				Public:         shareSvc,
				TrustedProxies: cfg.TrustedProxies,
			},
			Verification: shareSvc,
			// Public access-request submission/status. Gated on the repo
			// being configured (always is, here) — the gateway registers
			// /s/{token}/request-access + /s/{token}/request-status.
			AccessRequests: shareSvc,
			// HTTPS deployments mark the claim cookie Secure; local HTTP
			// dev leaves it off so the cookie is stored over localhost.
			SecureCookies: cfg.RequireTLS,
		})
		// Unused vault types just keep the build honest in case of future
		// wiring changes from the gateway to vault introspection.
		_ = vaultapp.Service{}
		_ = vaultinfra.EncryptedFSBoxEngine{}
	} else {
		sharesapi.RegisterPublicRoutes(mux, sharesapi.Deps{})
	}

	srv := &http.Server{Addr: cfg.ShareGatewayAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Infof("share gateway listening on %s", cfg.ShareGatewayAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("share gateway stopped: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func registerShareGatewayRoutes(mux *http.ServeMux, db *database.Connection) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","runtime":"share-gateway"}`))
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
		_, _ = w.Write([]byte(`{"status":"ready","runtime":"share-gateway"}`))
	})
}

// deriveMasterKey turns the SERVER_MASTER_KEY env value (hex) into a 32-byte
// AES-256 key via SHA-256. An empty string yields a deterministic zero-ish
// key that is useless for production but keeps local dev runnable.
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

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

// accessRequestTTL reads SHARE_ACCESS_REQUEST_TTL (a Go duration like "168h")
// for how long a pending access request stays open before the worker expires
// it. Defaults to 7 days. The gateway sets expires_at at submission time; the
// worker reads it. Both binaries default identically so a missing env yields
// consistent behavior.
func accessRequestTTL() time.Duration {
	if v := os.Getenv("SHARE_ACCESS_REQUEST_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 7 * 24 * time.Hour
}

// buildOTPDispatcher returns the email OTP dispatcher when SMTP is
// configured, else nil (require_otp shares are then only creatable in
// dev, where the code is echoed). Shared shape with cmd/api so the
// create-time guard and the verify-time delivery agree on availability.
func buildOTPDispatcher(cfg config.Config) sharesapp.OTPDispatcher {
	if cfg.OTPSMTPAddr == "" || cfg.OTPSMTPFrom == "" {
		return nil
	}
	return sharesinfra.NewSMTPOTPDispatcher(cfg.OTPSMTPAddr, cfg.OTPSMTPFrom, cfg.OTPSMTPUsername, cfg.OTPSMTPPassword)
}
