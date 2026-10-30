package infra

import (
	"context"
	"fmt"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type MemoryCredentialStore struct {
	mu          sync.RWMutex
	byUserID    map[string]domain.Credential
	emailLookup map[string]string
}

var _ app.CredentialStore = (*MemoryCredentialStore)(nil)

func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		byUserID:    map[string]domain.Credential{},
		emailLookup: map[string]string{},
	}
}

func (s *MemoryCredentialStore) Put(ctx context.Context, credential domain.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = ctx
	s.byUserID[credential.UserID] = credential
	return nil
}

func (s *MemoryCredentialStore) GetByUserID(ctx context.Context, userID string) (domain.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_ = ctx
	c, ok := s.byUserID[userID]
	if !ok {
		return domain.Credential{}, fmt.Errorf("credential not found")
	}
	return c, nil
}

func (s *MemoryCredentialStore) GetByEmail(ctx context.Context, email string) (domain.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_ = ctx
	userID, ok := s.emailLookup[email]
	if !ok {
		return domain.Credential{}, fmt.Errorf("credential not found")
	}
	c, ok := s.byUserID[userID]
	if !ok {
		return domain.Credential{}, fmt.Errorf("credential not found")
	}
	return c, nil
}
