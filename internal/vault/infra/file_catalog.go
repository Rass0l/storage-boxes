package infra

import (
	"context"
	"fmt"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type MemoryFileCatalog struct {
	mu      sync.RWMutex
	entries map[string]domain.FileEntry
}

var _ app.FileCatalogRepository = (*MemoryFileCatalog)(nil)

func NewMemoryFileCatalog() *MemoryFileCatalog {
	return &MemoryFileCatalog{entries: map[string]domain.FileEntry{}}
}

func (r *MemoryFileCatalog) PutFileEntry(ctx context.Context, entry domain.FileEntry) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[entry.ID] = entry
	return nil
}

func (r *MemoryFileCatalog) GetFileEntry(ctx context.Context, fileID string) (domain.FileEntry, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[fileID]
	if !ok {
		return domain.FileEntry{}, fmt.Errorf("file entry not found")
	}
	return entry, nil
}

func (r *MemoryFileCatalog) ListFiles(ctx context.Context, boxID string) ([]domain.FileEntry, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []domain.FileEntry{}
	for _, entry := range r.entries {
		if entry.BoxID == boxID {
			out = append(out, entry)
		}
	}
	return out, nil
}

func (r *MemoryFileCatalog) DeleteFileEntry(ctx context.Context, fileID string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, fileID)
	return nil
}

func (r *MemoryFileCatalog) GetByPath(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.entries {
		if entry.BoxID == boxID && entry.LogicalPath == logicalPath {
			return entry, nil
		}
	}
	return domain.FileEntry{}, fmt.Errorf("file entry not found at path")
}
