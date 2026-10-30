package infra

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// MemoryAccessRequestRepository is the in-memory AccessRequestRepository used
// by unit / docker-less integration tests.
//
// The join-based reconcile queries (ListPendingOnDeadShares,
// ListPendingWithActiveRecipient) need share / recipient state that lives in
// other repos. Like MemoryClaimRepository.Recipients, those are optional hooks:
// when nil the query returns no rows (the join can't be evaluated). The worker
// job test and the in-process integration wiring set them so the cleanup job
// is exercised against real state.
type MemoryAccessRequestRepository struct {
	mu   sync.RWMutex
	byID map[string]domain.AccessRequest

	// Recipients resolves and writes recipient rows: ListPendingWithActiveRecipient
	// reads via GetByShareEmail, and ApproveAtomic writes via Put /
	// ReactivateWithPasscode so an in-memory approval applies the request and
	// recipient mutation together (the PG repo uses a real transaction).
	Recipients interface {
		GetByShareEmail(ctx context.Context, shareID, emailNormalized string) (domain.Recipient, error)
		Put(ctx context.Context, r domain.Recipient) error
		ReactivateWithPasscode(ctx context.Context, recipientID string, salt, hash []byte, now time.Time) error
	}
	// Shares resolves the parent share so ListPendingOnDeadShares can test
	// deliverability.
	Shares interface {
		Get(ctx context.Context, shareID string) (domain.Share, error)
	}
}

var _ app.AccessRequestRepository = (*MemoryAccessRequestRepository)(nil)

func NewMemoryAccessRequestRepository() *MemoryAccessRequestRepository {
	return &MemoryAccessRequestRepository{byID: map[string]domain.AccessRequest{}}
}

func (m *MemoryAccessRequestRepository) Put(_ context.Context, ar domain.AccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Enforce the same partial-unique invariant the PG schema does: at most
	// one pending request per (share, email). A second pending insert is the
	// race backstop and surfaces as a conflict the service treats as a dup.
	if ar.Status == domain.AccessRequestPending {
		for _, e := range m.byID {
			if e.ShareID == ar.ShareID && e.RequesterEmailNormalized == ar.RequesterEmailNormalized &&
				e.Status == domain.AccessRequestPending {
				return fmt.Errorf("pending access request already exists")
			}
		}
	}
	m.byID[ar.ID] = ar
	return nil
}

func (m *MemoryAccessRequestRepository) Get(_ context.Context, id string) (domain.AccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ar, ok := m.byID[id]
	if !ok {
		return domain.AccessRequest{}, fmt.Errorf("access request not found")
	}
	return ar, nil
}

func (m *MemoryAccessRequestRepository) GetPendingByShareEmail(_ context.Context, shareID, emailNormalized string) (domain.AccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ar := range m.byID {
		if ar.ShareID == shareID && ar.RequesterEmailNormalized == emailNormalized && ar.Status == domain.AccessRequestPending {
			return ar, nil
		}
	}
	return domain.AccessRequest{}, fmt.Errorf("access request not found")
}

func (m *MemoryAccessRequestRepository) GetLatestByShareEmail(_ context.Context, shareID, emailNormalized string) (domain.AccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var latest domain.AccessRequest
	found := false
	for _, ar := range m.byID {
		if ar.ShareID != shareID || ar.RequesterEmailNormalized != emailNormalized {
			continue
		}
		if !found || ar.CreatedAt.After(latest.CreatedAt) {
			latest = ar
			found = true
		}
	}
	if !found {
		return domain.AccessRequest{}, fmt.Errorf("access request not found")
	}
	return latest, nil
}

func (m *MemoryAccessRequestRepository) ListByShare(_ context.Context, shareID, statusFilter string, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	m.mu.RLock()
	out := []domain.AccessRequest{}
	for _, ar := range m.byID {
		if ar.ShareID != shareID {
			continue
		}
		if statusFilter != "" && ar.Status != statusFilter {
			continue
		}
		out = append(out, ar)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryAccessRequestRepository) Decide(_ context.Context, id, status, recipientID, decidedBy, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("access request not found")
	}
	// Status-guarded: only a pending row transitions. Anything else is a
	// lost race / already-decided no-op, surfaced as the shared sentinel.
	if ar.Status != domain.AccessRequestPending {
		return app.ErrAccessRequestNotPending
	}
	ar.Status = status
	if recipientID != "" {
		ar.RecipientID = recipientID
	}
	ar.DecidedBy = decidedBy
	t := now
	ar.DecidedAt = &t
	ar.DecisionReason = reason
	m.byID[id] = ar
	return nil
}

// ApproveAtomic applies the request claim + recipient write under the AR lock
// so the in-memory model exposes the same all-or-nothing contract as the PG
// transaction: a non-pending request (lost race) writes nothing, and a
// recipient-write failure leaves the request pending.
func (m *MemoryAccessRequestRepository) ApproveAtomic(ctx context.Context, plan app.ApprovalPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.byID[plan.RequestID]
	if !ok {
		return fmt.Errorf("access request not found")
	}
	if ar.Status != domain.AccessRequestPending {
		return app.ErrAccessRequestNotPending
	}
	// Recipient write first: a failure here returns before the request is
	// marked approved, so the request stays pending and retryable.
	switch plan.Mode {
	case app.ApprovalModeNew:
		if m.Recipients == nil {
			return fmt.Errorf("recipients hook not wired")
		}
		if err := m.Recipients.Put(ctx, plan.Recipient); err != nil {
			return err
		}
	case app.ApprovalModeReactivate:
		if m.Recipients == nil {
			return fmt.Errorf("recipients hook not wired")
		}
		if err := m.Recipients.ReactivateWithPasscode(ctx, plan.Recipient.ID, plan.Recipient.PasscodeSalt, plan.Recipient.PasscodeHash, plan.Now); err != nil {
			return err
		}
	case app.ApprovalModeLink:
		// Recipient already active; nothing to write.
	default:
		return fmt.Errorf("unknown approval mode %q", plan.Mode)
	}
	ar.Status = domain.AccessRequestApproved
	ar.RecipientID = plan.Recipient.ID
	ar.DecidedBy = plan.DecidedBy
	t := plan.Now
	ar.DecidedAt = &t
	ar.DecisionReason = plan.Reason
	m.byID[plan.RequestID] = ar
	return nil
}

func (m *MemoryAccessRequestRepository) SupersedeOrphanedApprovals(_ context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []domain.AccessRequest{}
	for id, ar := range m.byID {
		if ar.Status != domain.AccessRequestApproved || ar.RecipientID != "" {
			continue
		}
		ar.Status = domain.AccessRequestSuperseded
		ar.DecisionReason = domain.AccessReasonRecipientMissing
		if ar.DecidedAt == nil {
			t := now
			ar.DecidedAt = &t
		}
		m.byID[id] = ar
		out = append(out, ar)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryAccessRequestRepository) ListPendingExpired(_ context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if limit <= 0 {
		limit = 200
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.AccessRequest{}
	for _, ar := range m.byID {
		if ar.Status != domain.AccessRequestPending {
			continue
		}
		if ar.ExpiresAt == nil || ar.ExpiresAt.After(now) {
			continue
		}
		out = append(out, ar)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryAccessRequestRepository) ListPendingOnDeadShares(ctx context.Context, now time.Time, limit int) ([]domain.AccessRequest, error) {
	if m.Shares == nil {
		return []domain.AccessRequest{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	m.mu.RLock()
	pending := make([]domain.AccessRequest, 0, len(m.byID))
	for _, ar := range m.byID {
		if ar.Status == domain.AccessRequestPending {
			pending = append(pending, ar)
		}
	}
	m.mu.RUnlock()
	out := []domain.AccessRequest{}
	for _, ar := range pending {
		share, err := m.Shares.Get(ctx, ar.ShareID)
		if err != nil || !share.IsDeliverable(now) {
			out = append(out, ar)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *MemoryAccessRequestRepository) ListPendingWithActiveRecipient(ctx context.Context, limit int) ([]domain.AccessRequest, error) {
	if m.Recipients == nil {
		return []domain.AccessRequest{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	m.mu.RLock()
	pending := make([]domain.AccessRequest, 0, len(m.byID))
	for _, ar := range m.byID {
		if ar.Status == domain.AccessRequestPending {
			pending = append(pending, ar)
		}
	}
	m.mu.RUnlock()
	out := []domain.AccessRequest{}
	for _, ar := range pending {
		rec, err := m.Recipients.GetByShareEmail(ctx, ar.ShareID, ar.RequesterEmailNormalized)
		if err == nil && rec.ID != "" && rec.RevokedAt == nil {
			out = append(out, ar)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *MemoryAccessRequestRepository) CountRecentByShareIP(_ context.Context, shareID, remoteIP string, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, ar := range m.byID {
		if ar.ShareID != shareID || ar.CreatedAt.Before(since) {
			continue
		}
		if remoteIP != "" && ar.RemoteIP != remoteIP {
			continue
		}
		n++
	}
	return n, nil
}

func (m *MemoryAccessRequestRepository) DeleteByShare(_ context.Context, shareID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ar := range m.byID {
		if ar.ShareID == shareID {
			delete(m.byID, id)
		}
	}
	return nil
}
