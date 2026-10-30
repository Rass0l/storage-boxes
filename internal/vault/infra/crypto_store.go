package infra

import (
	"context"
	"fmt"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type MemoryCryptoStore struct {
	mu sync.RWMutex
	m  map[string]domain.BoxCryptoMaterial
}

var _ app.CryptoStore = (*MemoryCryptoStore)(nil)

func NewMemoryCryptoStore() *MemoryCryptoStore {
	return &MemoryCryptoStore{m: map[string]domain.BoxCryptoMaterial{}}
}

func (s *MemoryCryptoStore) Put(ctx context.Context, m domain.BoxCryptoMaterial) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[m.BoxID] = m
	return nil
}

func (s *MemoryCryptoStore) Get(ctx context.Context, boxID string) (domain.BoxCryptoMaterial, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.m[boxID]
	if !ok {
		return domain.BoxCryptoMaterial{}, fmt.Errorf("box crypto material not found")
	}
	return m, nil
}

func (s *MemoryCryptoStore) Delete(ctx context.Context, boxID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, boxID)
	return nil
}
