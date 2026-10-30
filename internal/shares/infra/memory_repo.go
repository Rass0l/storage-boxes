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

type MemoryShareRepository struct {
	mu          sync.RWMutex
	shares      map[string]domain.Share
	tokenHashes map[string]string
}

var _ app.ShareRepository = (*MemoryShareRepository)(nil)

func NewMemoryShareRepository() *MemoryShareRepository {
	return &MemoryShareRepository{shares: map[string]domain.Share{}, tokenHashes: map[string]string{}}
}

func (r *MemoryShareRepository) Put(ctx context.Context, share domain.Share) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shares[share.ID] = share
	r.tokenHashes[share.TokenHash] = share.ID
	return nil
}

func (r *MemoryShareRepository) Get(ctx context.Context, shareID string) (domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	share, ok := r.shares[shareID]
	if !ok {
		return domain.Share{}, fmt.Errorf("share not found")
	}
	return share, nil
}

func (r *MemoryShareRepository) GetByTokenHash(ctx context.Context, tokenHash string) (domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.tokenHashes[tokenHash]
	if !ok {
		return domain.Share{}, fmt.Errorf("share not found")
	}
	return r.shares[id], nil
}

func (r *MemoryShareRepository) ListByBox(ctx context.Context, boxID string) ([]domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.Share{}
	for _, s := range r.shares {
		if s.BoxID == boxID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r *MemoryShareRepository) ListByCreator(ctx context.Context, userID string) ([]domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.Share{}
	for _, s := range r.shares {
		if s.CreatedBy == userID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r *MemoryShareRepository) UpdateStatus(ctx context.Context, shareID, status string, now time.Time) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.shares[shareID]
	if !ok {
		return fmt.Errorf("share not found")
	}
	s.Status = status
	if status == domain.StatusRevoked {
		t := now
		s.RevokedAt = &t
	}
	r.shares[shareID] = s
	return nil
}

func (r *MemoryShareRepository) UpdateSettings(ctx context.Context, shareID string, expiresAt time.Time, maxDownloads int) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.shares[shareID]
	if !ok {
		return fmt.Errorf("share not found")
	}
	s.ExpiresAt = expiresAt
	s.MaxDownloads = maxDownloads
	r.shares[shareID] = s
	return nil
}

func (r *MemoryShareRepository) IncrementDownload(ctx context.Context, shareID string, now time.Time) (int, error) {
	_ = ctx
	_ = now
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.shares[shareID]
	if !ok {
		return 0, fmt.Errorf("share not found")
	}
	s.DownloadCount++
	r.shares[shareID] = s
	return s.DownloadCount, nil
}

func (r *MemoryShareRepository) ListExpired(ctx context.Context, now time.Time, limit int) ([]domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.Share{}
	for _, s := range r.shares {
		if s.Status == domain.StatusActive && !s.ExpiresAt.After(now) {
			out = append(out, s)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryShareRepository) ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Share, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.Share{}
	for _, s := range r.shares {
		if s.PurgeRequestedAt != nil && s.Status != domain.StatusPurged {
			out = append(out, s)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryShareRepository) MarkPurgeRequested(ctx context.Context, shareID string, now time.Time) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.shares[shareID]
	if !ok {
		return fmt.Errorf("share not found")
	}
	t := now
	s.PurgeRequestedAt = &t
	r.shares[shareID] = s
	return nil
}

func (r *MemoryShareRepository) Delete(ctx context.Context, shareID string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.shares[shareID]
	if ok {
		delete(r.tokenHashes, s.TokenHash)
	}
	delete(r.shares, shareID)
	return nil
}

// MemoryShareObjectStore is the in-memory ShareObjectStore used by tests.
type MemoryShareObjectStore struct {
	mu      sync.RWMutex
	objects map[string]domain.ShareObject
}

var _ app.ShareObjectStore = (*MemoryShareObjectStore)(nil)

func NewMemoryShareObjectStore() *MemoryShareObjectStore {
	return &MemoryShareObjectStore{objects: map[string]domain.ShareObject{}}
}

func (s *MemoryShareObjectStore) PutObject(ctx context.Context, o domain.ShareObject) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[o.ShareID] = o
	return nil
}

func (s *MemoryShareObjectStore) GetObject(ctx context.Context, shareID string) (domain.ShareObject, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.objects[shareID]
	if !ok {
		return domain.ShareObject{}, fmt.Errorf("share object not found")
	}
	return o, nil
}

func (s *MemoryShareObjectStore) DeleteObject(ctx context.Context, shareID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, shareID)
	return nil
}

// MemoryAccessRecorder stores share_access_events in RAM.
type MemoryAccessRecorder struct {
	mu     sync.RWMutex
	events []domain.AccessEvent
}

var _ app.ShareAccessRecorder = (*MemoryAccessRecorder)(nil)

func NewMemoryAccessRecorder() *MemoryAccessRecorder { return &MemoryAccessRecorder{} }

func (r *MemoryAccessRecorder) RecordAccess(ctx context.Context, e domain.AccessEvent) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *MemoryAccessRecorder) ListByShare(ctx context.Context, shareID string, limit int) ([]domain.AccessEvent, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.AccessEvent{}
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].ShareID != shareID {
			continue
		}
		out = append(out, r.events[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *MemoryAccessRecorder) ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.AccessEvent, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.AccessEvent{}
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].RecipientID != recipientID {
			continue
		}
		out = append(out, r.events[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
