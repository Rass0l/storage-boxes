package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	auditapi "github.com/Rass0l/storage-boxes/internal/audit/api"
	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditinfra "github.com/Rass0l/storage-boxes/internal/audit/infra"
	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
	identityinfra "github.com/Rass0l/storage-boxes/internal/identity/infra"
	jobsapp "github.com/Rass0l/storage-boxes/internal/jobs/app"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/config"
	"github.com/Rass0l/storage-boxes/internal/platform/database"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	sharesapi "github.com/Rass0l/storage-boxes/internal/shares/api"
	sharesapp "github.com/Rass0l/storage-boxes/internal/shares/app"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
	vaultapi "github.com/Rass0l/storage-boxes/internal/vault/api"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// App owns the wired dependency graph for the API process.
type App struct {
	Config       config.Config
	DB           *database.Connection
	Handler      http.Handler
	Identity     *identityapp.Service
	Vault        *vaultapp.Service
	StopSweepers func()
	// Persistent indicates that stores are Postgres-backed (survive restart).
	Persistent bool
	// For memory-mode convenience.
	MemorySessions *identityinfra.MemorySessionStore
	// For pg-mode convenience (sweepers).
	PGSessions *identityinfra.PGSessionStore
	PGUnlocks  *vaultinfra.PGUnlockSessionStore

	// Test-only hook exposing the live share service so the shares
	// integration test can call the public-delivery path without standing
	// up a separate share-gateway process.
	testShares *sharesapp.Service
	// testBoxPurge exposes the worker's BoxPurgeJob so integration tests
	// can drive the soft-delete → finalize workflow without spawning
	// the cmd/worker binary.
	testBoxPurge *jobsapp.BoxPurgeJob
	// testAccessReqCleanup exposes the worker's AccessRequestCleanupJob so
	// integration tests can drive access-request reconciliation in-process.
	testAccessReqCleanup *jobsapp.AccessRequestCleanupJob
}

type SeedAdmin struct {
	Email       string
	DisplayName string
	Password    string
}

func DefaultSeedAdmin(cfg config.Config) SeedAdmin {
	email := getenv("SEED_ADMIN_EMAIL", "admin@example.local")
	pass := getenv("SEED_ADMIN_PASSWORD", "admin-dev-password-change-me")
	name := getenv("SEED_ADMIN_DISPLAY_NAME", "Administrator")
	_ = cfg
	return SeedAdmin{Email: email, DisplayName: name, Password: pass}
}

func getenv(key, fallback string) string {
	if v := envLookup(key); v != "" {
		return v
	}
	return fallback
}

func BuildApp(cfg config.Config, db *database.Connection) (*App, error) {
	clk := clock.RealClock{}
	persistent := db != nil && !db.IsMemory()
	idleTimeout := 24 * time.Hour
	absoluteTimeout := 7 * 24 * time.Hour

	var (
		users       identityapp.UserStore
		creds       identityapp.CredentialStore
		sessionsSvc identityapp.SessionService
		roleStore   identityapp.RoleStore

		boxes       vaultapp.BoxRepository
		cryptoStore vaultapp.CryptoStore
		filesRepo   vaultapp.FileCatalogRepository
		unlocks     vaultapp.UnlockSessionStore

		memSessions *identityinfra.MemorySessionStore
		pgSessions  *identityinfra.PGSessionStore
		pgUnlocks   *vaultinfra.PGUnlockSessionStore
	)

	if persistent {
		pool := db.Pool()
		users = identityinfra.NewPGUserStore(pool)
		creds = identityinfra.NewPGCredentialStore(pool)
		pgSessions = identityinfra.NewPGSessionStore(pool, identityinfra.PGSessionOptions{
			IdleTimeout: idleTimeout, AbsoluteTimeout: absoluteTimeout, Clock: clk,
		})
		sessionsSvc = pgSessions
		roleStore = identityinfra.NewPGRoleStore(pool)

		boxes = vaultinfra.NewPGBoxRepository(pool)
		cryptoStore = vaultinfra.NewPGCryptoStore(pool)
		filesRepo = vaultinfra.NewPGFileCatalog(pool)
		pgUnlocks = vaultinfra.NewPGUnlockSessionStore(pool)
		unlocks = pgUnlocks
	} else {
		mu := identityinfra.NewMemoryUserStore()
		mc := identityinfra.NewMemoryCredentialStore()
		mr := identityinfra.NewMemoryRoleStore()
		ms := identityinfra.NewMemorySessionStore(identityinfra.SessionOptions{
			IdleTimeout: idleTimeout, AbsoluteTimeout: absoluteTimeout, Clock: clk,
		})
		users, creds, roleStore, sessionsSvc = mu, mc, mr, ms
		memSessions = ms

		boxes = vaultinfra.NewMemoryBoxRepository()
		cryptoStore = vaultinfra.NewMemoryCryptoStore()
		filesRepo = vaultinfra.NewMemoryFileCatalog()
		unlocks = vaultinfra.NewMemoryUnlockSessionStore()
	}

	identitySvc := identityapp.NewService(identityapp.Deps{
		Users:       users,
		Credentials: creds,
		Sessions:    sessionsSvc,
		Roles:       roleStore,
		Hasher:      identityinfra.NewPasswordHasher(),
		IDs:         ids.RandomGenerator{},
		Clock:       clk,
	})

	if err := ensureSeedAdmin(identitySvc, roleStore, DefaultSeedAdmin(cfg)); err != nil {
		return nil, fmt.Errorf("seed admin: %w", err)
	}

	vaultSvc := vaultapp.NewService(vaultapp.ServiceDeps{
		Boxes:   boxes,
		Crypto:  cryptoStore,
		Files:   filesRepo,
		Unlocks: unlocks,
		Engine:  vaultinfra.NewEncryptedFSBoxEngine(getenv("BOX_STORAGE_ROOT", "./.box-storage")),
		IDs:     ids.RandomGenerator{},
		Clock:   clk,
	})

	mux := http.NewServeMux()
	registerCommonRoutes(mux, db)
	identityapi.RegisterRoutes(mux, identityapi.Deps{
		Service:       identitySvc,
		SecureCookies: cfg.RequireTLS || config.IsProductionLike(cfg.AppEnv),
		IdleTimeout:   idleTimeout,
	})
	vaultapi.RegisterRoutes(mux, vaultapi.Deps{Vault: vaultSvc, Identity: identitySvc})

	// Audit + shares services need a repository backing. In pg mode they
	// write to real tables; in memory mode we wire in-RAM equivalents so
	// the cross-package tests still exercise recording + listing.
	var auditSvc auditapp.AuditService
	var shareSvc *sharesapp.Service
	var shareRepoHandle sharesapp.ShareRepository
	var shareObjStore sharesapp.ShareObjectStore
	var shareStage sharesapp.StageEngine
	var accessReqRepo sharesapp.AccessRequestRepository
	accessReqTTL := accessRequestTTL()
	// In production-like environments require_otp shares deliver the code
	// out-of-band via the configured OTP dispatcher (SHARE_OTP_SMTP_*). In
	// dev/test the code is surfaced in the verify response instead, so the
	// flow is exercisable without external delivery infra. The API must
	// agree with the gateway on dispatcher availability because the
	// create-time guard lives here.
	devOTPEcho := !config.IsProductionLike(cfg.AppEnv)
	otpDispatcher := buildOTPDispatcher(cfg)
	if persistent {
		pool := db.Pool()
		auditSvc = auditapp.NewService(auditapp.Deps{
			Repo:    auditinfra.NewPGAuditRepository(pool),
			Outbox:  auditinfra.NewPGOutboxRepository(pool),
			Signals: auditinfra.NewPGRiskSignalRepository(pool),
			Clock:   clk,
			IDs:     ids.RandomGenerator{},
		})
		shareRepoHandle = sharesinfra.NewPGShareRepository(pool)
		shareObjStore = sharesinfra.NewPGShareObjectStore(pool)
		access := sharesinfra.NewPGAccessRecorder(pool)
		recipients := sharesinfra.NewPGRecipientRepository(pool)
		challenges := sharesinfra.NewPGChallengeRepository(pool)
		claims := sharesinfra.NewPGClaimRepository(pool)
		accessReqRepo = sharesinfra.NewPGAccessRequestRepository(pool)
		stageRoot := getenv("SHARE_STAGE_ROOT", "./.share-stage")
		shareStage = sharesinfra.NewShareStageEngine(stageRoot, deriveMasterKeyForShares(cfg.ServerMasterKey), vaultSvc)
		shareSvc = sharesapp.NewService(sharesapp.Deps{
			Shares:           shareRepoHandle,
			Objects:          shareObjStore,
			AccessLog:        access,
			Recipients:       recipients,
			Challenges:       challenges,
			Claims:           claims,
			AccessRequests:   accessReqRepo,
			AccessRequestTTL: accessReqTTL,
			Files:            &sharesinfra.VaultFileLookup{V: vaultSvc},
			Stage:            shareStage,
			Tokens:           sharesinfra.RandomTokenService{},
			Audit:            auditSvc,
			Clock:            clk,
			IDs:              ids.RandomGenerator{},
			OTPDispatcher:    otpDispatcher,
			DevModeOTPEcho:   devOTPEcho,
		})
	} else {
		auditSvc = auditapp.NewService(auditapp.Deps{
			Repo:    auditinfra.NewMemoryAuditRepository(),
			Outbox:  auditinfra.NewMemoryOutbox(),
			Signals: auditinfra.NewMemoryRiskSignals(),
			Clock:   clk,
			IDs:     ids.RandomGenerator{},
		})
		stageRoot := getenv("SHARE_STAGE_ROOT", "./.share-stage")
		shareRepoHandle = sharesinfra.NewMemoryShareRepository()
		shareObjStore = sharesinfra.NewMemoryShareObjectStore()
		shareStage = sharesinfra.NewShareStageEngine(stageRoot, deriveMasterKeyForShares(cfg.ServerMasterKey), vaultSvc)
		memRecipients := sharesinfra.NewMemoryRecipientRepository()
		memAccessReq := sharesinfra.NewMemoryAccessRequestRepository()
		// Wire the reconcile hooks so the in-process AccessRequestCleanupJob
		// (exposed for integration tests) resolves share/recipient state.
		memAccessReq.Recipients = memRecipients
		memAccessReq.Shares = shareRepoHandle
		accessReqRepo = memAccessReq
		shareSvc = sharesapp.NewService(sharesapp.Deps{
			Shares:           shareRepoHandle,
			Objects:          shareObjStore,
			AccessLog:        sharesinfra.NewMemoryAccessRecorder(),
			Recipients:       memRecipients,
			Challenges:       sharesinfra.NewMemoryChallengeRepository(),
			Claims:           sharesinfra.NewMemoryClaimRepository(),
			AccessRequests:   memAccessReq,
			AccessRequestTTL: accessReqTTL,
			Files:            &sharesinfra.VaultFileLookup{V: vaultSvc},
			Stage:            shareStage,
			Tokens:           sharesinfra.RandomTokenService{},
			Audit:            auditSvc,
			Clock:            clk,
			IDs:              ids.RandomGenerator{},
			OTPDispatcher:    otpDispatcher,
			DevModeOTPEcho:   devOTPEcho,
		})
	}
	sharesapi.RegisterRoutes(mux, sharesapi.Deps{
		Service:       shareSvc,
		Restricted:    shareSvc,
		Public:        shareSvc,
		Vault:         vaultSvc,
		Identity:      identitySvc,
		PublicBaseURL: getenv("SHARE_PUBLIC_BASE_URL", ""),
	})
	auditapi.RegisterRoutes(mux, auditapi.Deps{Service: auditSvc, Identity: identitySvc})
	identityapi.AttachAudit(identitySvc, auditSvc)
	vaultapi.AttachAudit(vaultSvc, auditSvc)
	// Cascade: when a box is soft-deleted, stamp purge_requested on
	// each of its shares and best-effort drop their stage blobs. The
	// share rows survive; the worker's BoxPurgeJob finalizes the box
	// after every share has converged to `purged`.
	vaultSvc.SetBoxDeletionHook(vaultapp.BoxDeletionHookFunc(func(ctx context.Context, boxID string) error {
		return shareSvc.PurgeByBox(ctx, boxID)
	}))

	sweepInterval := 5 * time.Minute
	if cfg.AppEnv == "test" {
		sweepInterval = 0
	}
	var stop func()
	if sweepInterval > 0 {
		stop = startSweepers(sweepInterval, memSessions, vaultSvc.UnlockCache())
	}

	// Assemble a BoxPurgeJob so tests (and, in future, an in-process
	// job loop) can drive the soft-delete → finalize workflow without
	// spinning up cmd/worker. Production path is cmd/worker.
	sharePurgeForTest := jobsapp.SharePurgeJob{
		Shares: shareRepoHandle, Objects: shareObjStore, Stage: shareStage, Audit: auditSvc,
	}
	boxPurgeForTest := &jobsapp.BoxPurgeJob{
		Boxes:  apiBoxFinalizer{svc: vaultSvc},
		Shares: shareRepoHandle,
		Purger: sharePurgeForTest,
		Audit:  auditSvc,
	}
	accessReqCleanupForTest := &jobsapp.AccessRequestCleanupJob{
		Requests: accessReqRepo,
		Audit:    auditSvc,
	}

	return &App{
		Config:               cfg,
		DB:                   db,
		Handler:              mux,
		Identity:             identitySvc,
		Vault:                vaultSvc,
		StopSweepers:         stop,
		Persistent:           persistent,
		MemorySessions:       memSessions,
		PGSessions:           pgSessions,
		PGUnlocks:            pgUnlocks,
		testShares:           shareSvc,
		testBoxPurge:         boxPurgeForTest,
		testAccessReqCleanup: accessReqCleanupForTest,
	}, nil
}

// accessRequestTTL reads SHARE_ACCESS_REQUEST_TTL (a Go duration like "168h")
// for how long a pending access request stays open before the worker expires
// it. Defaults to 7 days when unset or unparsable.
func accessRequestTTL() time.Duration {
	if v := envLookup("SHARE_ACCESS_REQUEST_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 7 * 24 * time.Hour
}

// apiBoxFinalizer adapts *vaultapp.Service to jobsapp.BoxFinalizer. Kept
// next to BuildApp so cmd/worker and cmd/api share one pattern.
type apiBoxFinalizer struct{ svc *vaultapp.Service }

func (a apiBoxFinalizer) ListPurgeCandidateBoxes(ctx context.Context, limit int) ([]jobsapp.BoxRef, error) {
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

func (a apiBoxFinalizer) FinalizeBox(ctx context.Context, boxID string) error {
	return a.svc.FinalizeBox(ctx, boxID)
}

// ensureSeedAdmin idempotently installs the bootstrap admin. In pg mode the
// user row may already exist from migration 010 or a prior restart — that's
// fine: we log-and-continue on unique conflicts, but still enforce the role
// binding.
func ensureSeedAdmin(svc *identityapp.Service, roles identityapp.RoleStore, seed SeedAdmin) error {
	ctx := context.Background()
	user, err := svc.CreateUser(ctx, identityapp.CreateUserInput{
		Email: seed.Email, DisplayName: seed.DisplayName, Password: seed.Password,
	})
	if err != nil {
		// Already-seeded is not an error here. Rehash the password against
		// the current SEED_ADMIN_PASSWORD so the env stays authoritative.
		if isAlreadyExists(err) {
			existing, lookupErr := svc.UserByEmail(ctx, seed.Email)
			if lookupErr != nil {
				return lookupErr
			}
			if err := svc.UpsertCredentialPassword(ctx, existing.ID, seed.Password); err != nil {
				return err
			}
			return roles.Bind(ctx, existing.ID, "admin")
		}
		return err
	}
	return roles.Bind(ctx, user.ID, "admin")
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, errAlreadyExistsSentinel) ||
		// fallback string match on the platform error code
		(len(msg) > 0 && (contains(msg, "email_in_use") || contains(msg, "duplicate key")))
}

var errAlreadyExistsSentinel = errors.New("already exists")

// deriveMasterKeyForShares converts the hex-encoded SERVER_MASTER_KEY into a
// fixed 32-byte AES-256 key for the share stage engine. Empty input yields
// a zero key which is unusable for real shares but keeps local bring-up
// simple — config validation catches this before production.
func deriveMasterKeyForShares(hexKey string) []byte {
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

// buildOTPDispatcher returns the email OTP dispatcher when SMTP is
// configured, else nil. The API constructs it so the create-time
// require_otp guard agrees with the gateway's verify-time delivery on
// whether OTP shares are operable.
func buildOTPDispatcher(cfg config.Config) sharesapp.OTPDispatcher {
	if cfg.OTPSMTPAddr == "" || cfg.OTPSMTPFrom == "" {
		return nil
	}
	return sharesinfra.NewSMTPOTPDispatcher(cfg.OTPSMTPAddr, cfg.OTPSMTPFrom, cfg.OTPSMTPUsername, cfg.OTPSMTPPassword)
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
