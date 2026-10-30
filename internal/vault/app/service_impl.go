package app

import (
	"context"
	"strings"
	"time"

	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/vault/crypto"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// ServiceDeps bundles VaultService collaborators.
type ServiceDeps struct {
	Boxes         BoxRepository
	Crypto        CryptoStore
	Files         FileCatalogRepository
	Unlocks       UnlockSessionStore
	UnlockCache   *UnlockCache
	Engine        BoxEngine
	IDs           ids.IDGenerator
	Clock         clock.Clock
	UnlockTimeout time.Duration
	// BoxDeletionHook is invoked after a box row is deleted and before
	// the engine directory is torn down. The vault service owns box
	// lifecycle; downstream subsystems (shares) register their own
	// cleanup here so their on-disk state stays consistent with the
	// cascaded FK deletes in Postgres. Nil-safe.
	BoxDeletionHook BoxDeletionHook
}

// BoxDeletionHook is the seam the shares subsystem plugs into so that
// stage blobs for the deleted box are removed before they orphan.
type BoxDeletionHook interface {
	OnBoxDeleted(ctx context.Context, boxID string) error
}

// BoxDeletionHookFunc adapts a plain function to the hook.
type BoxDeletionHookFunc func(ctx context.Context, boxID string) error

func (f BoxDeletionHookFunc) OnBoxDeleted(ctx context.Context, boxID string) error {
	return f(ctx, boxID)
}

// SetBoxDeletionHook swaps the hook at runtime (used by cmd/api wiring
// so that vault and shares services can be constructed independently).
func (s *Service) SetBoxDeletionHook(h BoxDeletionHook) { s.deps.BoxDeletionHook = h }

type Service struct {
	deps      ServiceDeps
	auditSink AuditSink
}

var _ VaultService = (*Service)(nil)

// UnlockCache exposes the in-memory BMK cache so callers (e.g. the sweeper
// goroutine in cmd/api) can invoke Sweep on a schedule.
func (s *Service) UnlockCache() *UnlockCache { return s.deps.UnlockCache }

func NewService(deps ServiceDeps) *Service {
	if deps.IDs == nil {
		deps.IDs = ids.RandomGenerator{}
	}
	if deps.Clock == nil {
		deps.Clock = clock.RealClock{}
	}
	if deps.UnlockTimeout <= 0 {
		deps.UnlockTimeout = 30 * time.Minute
	}
	if deps.UnlockCache == nil {
		deps.UnlockCache = NewUnlockCache(deps.Clock)
	}
	return &Service{deps: deps}
}

// CreateBoxFullInput adds the box password to the basic CreateBoxInput.
type CreateBoxFullInput struct {
	OwnerUserID string
	Name        string
	SizeBytes   int64
	Password    string
}

func (s *Service) CreateBoxFull(ctx context.Context, in CreateBoxFullInput) (domain.Box, error) {
	if strings.TrimSpace(in.Name) == "" {
		return domain.Box{}, platerr.New(platerr.CategoryValidation, "invalid_name", "box name required")
	}
	if len(in.Password) < 8 {
		return domain.Box{}, platerr.New(platerr.CategoryValidation, "weak_password", "box password must be at least 8 characters")
	}
	if in.SizeBytes <= 0 {
		in.SizeBytes = 1 << 30 // default 1 GiB quota
	}
	box := domain.Box{
		ID:          s.deps.IDs.New("box"),
		OwnerUserID: in.OwnerUserID,
		Name:        strings.TrimSpace(in.Name),
		SizeBytes:   in.SizeBytes,
		Status:      "active",
		CreatedAt:   s.deps.Clock.Now(),
	}
	bmk, err := crypto.GenerateBMK()
	if err != nil {
		return domain.Box{}, platerr.New(platerr.CategoryCrypto, "bmk_gen", err.Error())
	}
	salt, err := crypto.RandomSalt()
	if err != nil {
		return domain.Box{}, platerr.New(platerr.CategoryCrypto, "salt_gen", err.Error())
	}
	kek := crypto.DeriveKEK(in.Password, salt, crypto.DefaultKDFTime, crypto.DefaultKDFMemory, crypto.DefaultKDFThreads)
	nonce, ct, err := crypto.SealWithKEK(kek, bmk)
	if err != nil {
		return domain.Box{}, platerr.New(platerr.CategoryCrypto, "seal_bmk", err.Error())
	}
	material := domain.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: salt,
		KDFTime: crypto.DefaultKDFTime, KDFMemory: crypto.DefaultKDFMemory, KDFThreads: crypto.DefaultKDFThreads,
		CipherAlgo: "aes-256-gcm", Nonce: nonce, WrappedBMK: ct,
	}

	// Prefer atomic persistence when the store supports it so we never end
	// up with a box row that has no matching crypto material (or vice versa).
	if atomic, ok := s.deps.Boxes.(AtomicBoxCreator); ok {
		if err := atomic.PutBoxAtomic(ctx, box, material); err != nil {
			return domain.Box{}, platerr.New(platerr.CategoryInternal, "persist_box", err.Error())
		}
	} else {
		if err := s.deps.Boxes.Put(ctx, box); err != nil {
			return domain.Box{}, platerr.New(platerr.CategoryInternal, "persist_box", err.Error())
		}
		if err := s.deps.Crypto.Put(ctx, material); err != nil {
			// Best-effort rollback for the non-atomic path.
			_ = s.deps.Boxes.Delete(ctx, box.ID)
			return domain.Box{}, platerr.New(platerr.CategoryInternal, "persist_crypto", err.Error())
		}
	}
	if s.deps.Engine != nil {
		_ = s.deps.Engine.CreateBox(ctx, box.ID, box.SizeBytes)
	}
	s.emitAudit(ctx, "vault.box_created", "box", box.ID, in.OwnerUserID, map[string]any{"name": box.Name})
	return box, nil
}

// CreateBox satisfies VaultService. Real use should go via CreateBoxFull.
func (s *Service) CreateBox(ctx context.Context, in CreateBoxInput) (domain.Box, error) {
	return s.CreateBoxFull(ctx, CreateBoxFullInput{
		OwnerUserID: in.OwnerUserID, Name: in.Name, SizeBytes: in.SizeBytes,
		Password: "unset-password-change-me",
	})
}

func (s *Service) ListBoxes(ctx context.Context, ownerUserID string) ([]domain.Box, error) {
	return s.deps.Boxes.ListByOwner(ctx, ownerUserID)
}

func (s *Service) GetBox(ctx context.Context, boxID string) (domain.Box, error) {
	return s.deps.Boxes.Get(ctx, boxID)
}

// DeleteBox is the API-facing entry point for box removal. It flips the
// box to `status='deleting'` and fires the pre-delete hook so the
// shares subsystem can stamp `purge_requested_at` on each share it
// owns — but it does NOT hard-delete the row. The worker's
// BoxPurgeJob walks rows in the `deleting` state on a schedule, waits
// for every share to reach `purged`, and then calls FinalizeBox to
// issue the FK-cascading hard DELETE + wipe the engine directory.
//
// This split is what makes the deletion workflow truthful under
// failure: if the share-purge hook partially fails, the share rows
// still exist with `purge_requested_at` set, so the worker CAN and
// DOES retry them. The old code path hard-deleted the box row up
// front, FK CASCADE dropped every share row, and the worker had
// nothing left to retry against.
func (s *Service) DeleteBox(ctx context.Context, boxID, requesterID string) error {
	box, err := s.deps.Boxes.Get(ctx, boxID)
	if err != nil {
		return platerr.New(platerr.CategoryNotFound, "box_not_found", "box not found")
	}
	if box.OwnerUserID != requesterID {
		return platerr.New(platerr.CategoryAuthz, "forbidden", "not the box owner")
	}
	if box.Status == "deleting" {
		// Idempotent: already in the pipeline.
		return nil
	}
	now := s.deps.Clock.Now().UTC()
	if err := s.deps.Boxes.SoftDelete(ctx, boxID, now); err != nil {
		return platerr.New(platerr.CategoryInternal, "persist_soft_delete", err.Error())
	}
	// Revoke any active unlock sessions so the client can't keep using
	// a soft-deleted box's BMK between now and worker finalize.
	s.deps.UnlockCache.SweepBox(boxID)
	// Stamp purge_requested on every share tied to this box. A failure
	// here is surfaced as a partial audit record but does not block
	// deletion — unlike the old code path, the share rows still exist
	// for the worker to retry, and the box row itself is now
	// unreachable to the user.
	if s.deps.BoxDeletionHook != nil {
		if hookErr := s.deps.BoxDeletionHook.OnBoxDeleted(ctx, boxID); hookErr != nil {
			s.emitAudit(ctx, "vault.box_deletion_partial", "box", boxID, requesterID, map[string]any{
				"reason":       "share_hook_partial",
				"error":        hookErr.Error(),
				"worker_retry": true,
			})
		}
	}
	s.emitAudit(ctx, "vault.box_delete_requested", "box", boxID, requesterID, nil)
	return nil
}

// FinalizeBox is the hard-delete path. ONLY the worker's BoxPurgeJob
// should call this, and only after every share has converged to
// `purged`. Idempotent at the repo level: a second call on an
// already-gone row is a no-op.
//
// Ordering for durability: the on-disk blob wipe runs BEFORE the
// metadata hard-delete. If the engine wipe returns an error, the box
// row stays in `status='deleting'` and FinalizeBox returns — the next
// tick of BoxPurgeJob retries. The old ordering (metadata first, then
// best-effort blob wipe) left plaintext blobs orphaned on disk
// whenever the wipe failed, with no metadata pointing at them so no
// future tick could retry. That was a real durability gap; this
// ordering closes it.
//
// Crypto material is deleted explicitly before the metadata DELETE so
// the memory repo's non-FK semantics still tear down the full graph.
// In pg mode the `box_crypto_material` row is already dropped by the
// FK CASCADE that fires during FinalizeDelete — the explicit call is
// a harmless double-delete there.
func (s *Service) FinalizeBox(ctx context.Context, boxID string) error {
	box, err := s.deps.Boxes.Get(ctx, boxID)
	if err != nil {
		// Already gone — nothing to do.
		return nil
	}
	if box.Status != "deleting" {
		return platerr.New(platerr.CategoryConflict, "not_deleting",
			"FinalizeBox requires a box in the deleting state")
	}
	// Blob wipe first. A failure here must NOT hard-delete the
	// metadata; the row stays in `deleting` so a subsequent tick can
	// retry.
	if s.deps.Engine != nil {
		if err := s.deps.Engine.DeleteBox(ctx, boxID); err != nil {
			s.emitAudit(ctx, "vault.box_finalize_partial", "box", boxID, "", map[string]any{
				"reason": "engine_wipe_failed",
				"error":  err.Error(),
			})
			return platerr.New(platerr.CategoryInternal, "engine_wipe", err.Error())
		}
	}
	// Crypto material gone first (no-op under FK cascade, required in
	// memory mode).
	_ = s.deps.Crypto.Delete(ctx, boxID)
	if err := s.deps.Boxes.FinalizeDelete(ctx, boxID); err != nil {
		return platerr.New(platerr.CategoryInternal, "persist_finalize", err.Error())
	}
	s.emitAudit(ctx, "vault.box_deleted", "box", boxID, "", nil)
	return nil
}

// ListPurgeCandidateBoxes surfaces the in-flight soft-deletes for the
// worker's BoxPurgeJob. Kept on the service so the job doesn't need
// the repo handle directly.
func (s *Service) ListPurgeCandidateBoxes(ctx context.Context, limit int) ([]domain.Box, error) {
	return s.deps.Boxes.ListPurgeCandidates(ctx, limit)
}

func (s *Service) UnlockBox(ctx context.Context, boxID, userID, password string) (domain.UnlockSession, error) {
	box, err := s.deps.Boxes.Get(ctx, boxID)
	if err != nil {
		return domain.UnlockSession{}, platerr.New(platerr.CategoryNotFound, "box_not_found", "box not found")
	}
	if box.OwnerUserID != userID {
		return domain.UnlockSession{}, platerr.New(platerr.CategoryAuthz, "forbidden", "not the box owner")
	}
	if box.Status == "deleting" {
		return domain.UnlockSession{}, platerr.New(platerr.CategoryConflict, "box_deleting",
			"box is pending deletion and cannot be unlocked")
	}
	material, err := s.deps.Crypto.Get(ctx, boxID)
	if err != nil {
		return domain.UnlockSession{}, platerr.New(platerr.CategoryInternal, "crypto_missing", err.Error())
	}
	kek := crypto.DeriveKEK(password, material.KDFSalt, material.KDFTime, material.KDFMemory, material.KDFThreads)
	bmk, err := crypto.OpenWithKEK(kek, material.Nonce, material.WrappedBMK)
	if err != nil {
		s.emitAudit(ctx, "vault.box_unlock_failed", "box", boxID, userID, map[string]any{"reason": "bad_password"})
		return domain.UnlockSession{}, platerr.New(platerr.CategoryAuth, "invalid_password", "box password incorrect")
	}

	now := s.deps.Clock.Now()
	session := domain.UnlockSession{
		ID:        s.deps.IDs.New("unlock"),
		BoxID:     boxID,
		UserID:    userID,
		ExpiresAt: now.Add(s.deps.UnlockTimeout),
	}
	if err := s.deps.Unlocks.Put(ctx, session); err != nil {
		return domain.UnlockSession{}, platerr.New(platerr.CategoryInternal, "unlock_persist", err.Error())
	}
	s.deps.UnlockCache.Put(session.ID, boxID, userID, bmk, session.ExpiresAt)
	if s.deps.Engine != nil {
		_ = s.deps.Engine.UnlockBox(ctx, boxID)
	}
	s.emitAudit(ctx, "vault.box_unlocked", "box", boxID, userID, map[string]any{"session_id": session.ID})
	return session, nil
}

// LockBox closes an unlock session. The requester must own the session (or
// the session must be long gone). Unknown session IDs yield not_found so we
// don't leak existence to other tenants.
func (s *Service) LockBox(ctx context.Context, boxID, sessionID, requesterID string) error {
	unlock, err := s.deps.Unlocks.Get(ctx, sessionID)
	if err != nil {
		// Treat unknown as success: idempotent lock on a missing session.
		return nil
	}
	if unlock.UserID != requesterID {
		return platerr.New(platerr.CategoryAuthz, "forbidden", "unlock session belongs to another user")
	}
	if boxID != "" && unlock.BoxID != boxID {
		return platerr.New(platerr.CategoryValidation, "wrong_box", "unlock session is not for this box")
	}
	s.deps.UnlockCache.Delete(sessionID)
	return s.deps.Unlocks.Delete(ctx, sessionID)
}

// ResolveUnlock looks up an active unlock session by ID and returns the
// cached BMK context. Used by vault middleware.
func (s *Service) ResolveUnlock(ctx context.Context, sessionID string) (UnlockContext, error) {
	unlock, err := s.deps.Unlocks.Get(ctx, sessionID)
	if err != nil {
		return UnlockContext{}, platerr.New(platerr.CategoryAuth, "unlock_invalid", "unlock session not found")
	}
	if !unlock.ExpiresAt.After(s.deps.Clock.Now()) {
		s.deps.UnlockCache.Delete(sessionID)
		_ = s.deps.Unlocks.Delete(ctx, sessionID)
		return UnlockContext{}, platerr.New(platerr.CategoryAuth, "unlock_expired", "unlock session expired")
	}
	uc, ok := s.deps.UnlockCache.Lookup(sessionID)
	if !ok {
		// Catalog row still present but the in-memory BMK is gone (process
		// restart / sweep). Force a fresh unlock.
		_ = s.deps.Unlocks.Delete(ctx, sessionID)
		return UnlockContext{}, platerr.New(platerr.CategoryAuth, "unlock_expired", "unlock session no longer cached; re-unlock the box")
	}
	return uc, nil
}

func (s *Service) ListFiles(ctx context.Context, boxID string) ([]domain.FileEntry, error) {
	return s.deps.Files.ListFiles(ctx, boxID)
}
