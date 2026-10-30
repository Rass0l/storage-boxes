package infra

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// MemoryRecipientRepository is the in-memory RecipientRepository used by
// unit tests.
type MemoryRecipientRepository struct {
	mu   sync.RWMutex
	byID map[string]domain.Recipient
}

var _ app.RecipientRepository = (*MemoryRecipientRepository)(nil)

func NewMemoryRecipientRepository() *MemoryRecipientRepository {
	return &MemoryRecipientRepository{byID: map[string]domain.Recipient{}}
}

func (m *MemoryRecipientRepository) Put(_ context.Context, r domain.Recipient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[r.ID] = r
	return nil
}

// PutBatch inserts all recipients atomically (all-or-nothing), enforcing
// the same UNIQUE(share_id, email_normalized) invariant the PG schema
// does so unit tests exercise the real failure modes: a duplicate within
// the batch — or against an already-stored recipient — commits nothing.
func (m *MemoryRecipientRepository) PutBatch(_ context.Context, recipients []domain.Recipient) error {
	if len(recipients) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	batchKeys := map[string]struct{}{}
	for _, r := range recipients {
		key := r.ShareID + "\x00" + r.EmailNormalized
		if _, dup := batchKeys[key]; dup {
			return fmt.Errorf("duplicate recipient in batch: %s", r.EmailNormalized)
		}
		batchKeys[key] = struct{}{}
		for _, existing := range m.byID {
			if existing.ShareID == r.ShareID && existing.EmailNormalized == r.EmailNormalized {
				return fmt.Errorf("recipient already exists: %s", r.EmailNormalized)
			}
		}
	}
	// Validation passed for the whole batch — now commit every row.
	for _, r := range recipients {
		m.byID[r.ID] = r
	}
	return nil
}

func (m *MemoryRecipientRepository) Get(_ context.Context, id string) (domain.Recipient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.byID[id]
	if !ok {
		return domain.Recipient{}, fmt.Errorf("recipient not found")
	}
	return r, nil
}

func (m *MemoryRecipientRepository) GetByShareEmail(_ context.Context, shareID, emailNormalized string) (domain.Recipient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.byID {
		if r.ShareID == shareID && r.EmailNormalized == emailNormalized {
			return r, nil
		}
	}
	return domain.Recipient{}, fmt.Errorf("recipient not found")
}

func (m *MemoryRecipientRepository) ListByShare(_ context.Context, shareID string) ([]domain.Recipient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.Recipient{}
	for _, r := range m.byID {
		if r.ShareID == shareID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryRecipientRepository) UpdatePasscode(_ context.Context, id string, salt, hash []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("recipient not found")
	}
	r.PasscodeHash = hash
	r.PasscodeSalt = salt
	t := now
	r.PasscodeRotatedAt = &t
	r.FailedAttempts = 0
	m.byID[id] = r
	return nil
}

func (m *MemoryRecipientRepository) ReactivateWithPasscode(_ context.Context, id string, salt, hash []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("recipient not found")
	}
	r.RevokedAt = nil
	r.FailedAttempts = 0
	r.PasscodeHash = hash
	r.PasscodeSalt = salt
	t := now
	r.PasscodeRotatedAt = &t
	m.byID[id] = r
	return nil
}

func (m *MemoryRecipientRepository) MarkVerified(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("recipient not found")
	}
	if r.VerifiedAt == nil {
		t := now
		r.VerifiedAt = &t
	}
	m.byID[id] = r
	return nil
}

func (m *MemoryRecipientRepository) MarkAttempt(_ context.Context, id string, succeeded bool, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("recipient not found")
	}
	t := now
	r.LastAttemptAt = &t
	if succeeded {
		r.FailedAttempts = 0
	} else {
		r.FailedAttempts++
	}
	m.byID[id] = r
	return nil
}

func (m *MemoryRecipientRepository) Revoke(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("recipient not found")
	}
	if r.RevokedAt == nil {
		t := now
		r.RevokedAt = &t
	}
	m.byID[id] = r
	return nil
}

func (m *MemoryRecipientRepository) DeleteByShare(_ context.Context, shareID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.byID {
		if r.ShareID == shareID {
			delete(m.byID, id)
		}
	}
	return nil
}

// MemoryChallengeRepository is an append-only in-memory store used by tests.
type MemoryChallengeRepository struct {
	mu   sync.RWMutex
	rows []domain.Challenge
}

var _ app.ChallengeRepository = (*MemoryChallengeRepository)(nil)

func NewMemoryChallengeRepository() *MemoryChallengeRepository { return &MemoryChallengeRepository{} }

func (m *MemoryChallengeRepository) Append(_ context.Context, c domain.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, c)
	return nil
}

func (m *MemoryChallengeRepository) ListByShare(_ context.Context, shareID string, limit int) ([]domain.Challenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.Challenge{}
	for i := len(m.rows) - 1; i >= 0; i-- {
		if m.rows[i].ShareID != shareID {
			continue
		}
		out = append(out, m.rows[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryChallengeRepository) ListByRecipient(_ context.Context, recipientID string, limit int) ([]domain.Challenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.Challenge{}
	for i := len(m.rows) - 1; i >= 0; i-- {
		if m.rows[i].RecipientID != recipientID {
			continue
		}
		out = append(out, m.rows[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryChallengeRepository) RecentFailures(_ context.Context, shareID, remoteIP string, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, c := range m.rows {
		if c.ShareID != shareID || c.Succeeded {
			continue
		}
		if c.AttemptedAt.Before(since) {
			continue
		}
		if remoteIP != "" && c.RemoteIP != remoteIP {
			continue
		}
		n++
	}
	return n, nil
}

// MemoryClaimRepository backs tests.
type MemoryClaimRepository struct {
	mu   sync.RWMutex
	byID map[string]domain.Claim
	// Recipients, when set, lets ListActiveWithRevokedRecipient evaluate
	// the recipient join in memory (the PG repo does it in SQL). Left nil
	// the method returns no rows, since the join can't be computed
	// without recipient state. Wired by the worker/tests that exercise
	// reconciliation.
	Recipients interface {
		Get(ctx context.Context, id string) (domain.Recipient, error)
	}
}

var _ app.ClaimRepository = (*MemoryClaimRepository)(nil)

func NewMemoryClaimRepository() *MemoryClaimRepository {
	return &MemoryClaimRepository{byID: map[string]domain.Claim{}}
}

func (m *MemoryClaimRepository) Put(_ context.Context, c domain.Claim) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[c.ID] = c
	return nil
}

func (m *MemoryClaimRepository) GetByTokenHash(_ context.Context, h []byte) (domain.Claim, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.byID {
		if bytes.Equal(c.TokenHash, h) {
			return c, nil
		}
	}
	return domain.Claim{}, fmt.Errorf("claim not found")
}

func (m *MemoryClaimRepository) Get(_ context.Context, id string) (domain.Claim, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.byID[id]
	if !ok {
		return domain.Claim{}, fmt.Errorf("claim not found")
	}
	return c, nil
}

func (m *MemoryClaimRepository) ListByShare(_ context.Context, shareID string) ([]domain.Claim, error) {
	return m.filter(func(c domain.Claim) bool { return c.ShareID == shareID }), nil
}

func (m *MemoryClaimRepository) ListByRecipient(_ context.Context, recipientID string) ([]domain.Claim, error) {
	return m.filter(func(c domain.Claim) bool { return c.RecipientID == recipientID }), nil
}

func (m *MemoryClaimRepository) CompleteOTP(_ context.Context, id string, now time.Time) error {
	_ = now
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok || !c.OTPPending || c.RevokedAt != nil {
		return fmt.Errorf("claim not pending")
	}
	c.OTPPending = false
	c.OTPHash = nil
	c.OTPExpiresAt = nil
	m.byID[id] = c
	return nil
}

func (m *MemoryClaimRepository) Revoke(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("claim not found")
	}
	if c.RevokedAt == nil {
		t := now
		c.RevokedAt = &t
	}
	m.byID[id] = c
	return nil
}

func (m *MemoryClaimRepository) RevokeByRecipient(_ context.Context, recipientID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.byID {
		if c.RecipientID == recipientID && c.RevokedAt == nil {
			t := now
			c.RevokedAt = &t
			m.byID[id] = c
		}
	}
	return nil
}

func (m *MemoryClaimRepository) RevokeByShare(_ context.Context, shareID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.byID {
		if c.ShareID == shareID && c.RevokedAt == nil {
			t := now
			c.RevokedAt = &t
			m.byID[id] = c
		}
	}
	return nil
}

func (m *MemoryClaimRepository) ListExpired(_ context.Context, now time.Time, limit int) ([]domain.Claim, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.Claim{}
	for _, c := range m.byID {
		if c.RevokedAt != nil {
			continue
		}
		if c.ExpiresAt.IsZero() || c.ExpiresAt.After(now) {
			continue
		}
		out = append(out, c)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryClaimRepository) ListActiveWithRevokedRecipient(ctx context.Context, limit int) ([]domain.Claim, error) {
	if m.Recipients == nil {
		return []domain.Claim{}, nil
	}
	m.mu.RLock()
	active := make([]domain.Claim, 0, len(m.byID))
	for _, c := range m.byID {
		if c.RevokedAt == nil {
			active = append(active, c)
		}
	}
	m.mu.RUnlock()
	out := []domain.Claim{}
	for _, c := range active {
		rec, err := m.Recipients.Get(ctx, c.RecipientID)
		if err == nil && rec.RevokedAt != nil {
			out = append(out, c)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *MemoryClaimRepository) filter(pred func(domain.Claim) bool) []domain.Claim {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.Claim{}
	for _, c := range m.byID {
		if pred(c) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out
}
