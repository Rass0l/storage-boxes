package infra

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type MemoryBoxRepository struct {
	mu       sync.RWMutex
	boxes    map[string]domain.Box
	purgeReq map[string]time.Time
}

var _ app.BoxRepository = (*MemoryBoxRepository)(nil)

func NewMemoryBoxRepository() *MemoryBoxRepository {
	return &MemoryBoxRepository{boxes: map[string]domain.Box{}, purgeReq: map[string]time.Time{}}
}

func (r *MemoryBoxRepository) Put(ctx context.Context, box domain.Box) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.boxes[box.ID] = box
	return nil
}

func (r *MemoryBoxRepository) Get(ctx context.Context, boxID string) (domain.Box, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	box, ok := r.boxes[boxID]
	if !ok {
		return domain.Box{}, fmt.Errorf("box not found")
	}
	return box, nil
}

func (r *MemoryBoxRepository) Delete(ctx context.Context, boxID string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.boxes, boxID)
	delete(r.purgeReq, boxID)
	return nil
}

// SoftDelete flips status to 'deleting' and stamps purge_requested_at.
// The row stays queryable until the worker's BoxPurgeJob finalizes.
func (r *MemoryBoxRepository) SoftDelete(ctx context.Context, boxID string, now time.Time) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	box, ok := r.boxes[boxID]
	if !ok {
		return fmt.Errorf("box not found")
	}
	box.Status = "deleting"
	r.boxes[boxID] = box
	r.purgeReq[boxID] = now
	return nil
}

func (r *MemoryBoxRepository) ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Box, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.Box{}
	for id := range r.purgeReq {
		if box, ok := r.boxes[id]; ok {
			out = append(out, box)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryBoxRepository) FinalizeDelete(ctx context.Context, boxID string) error {
	return r.Delete(ctx, boxID)
}

func (r *MemoryBoxRepository) ListByOwner(ctx context.Context, ownerUserID string) ([]domain.Box, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []domain.Box
	for _, box := range r.boxes {
		if box.OwnerUserID != ownerUserID {
			continue
		}
		// Hide soft-deleted boxes from normal listings; operators still
		// see them via ListPurgeCandidates.
		if box.Status == "deleting" {
			continue
		}
		out = append(out, box)
	}
	return out, nil
}
