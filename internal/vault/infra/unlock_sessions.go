package infra

import (
	"context"
	"fmt"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type MemoryUnlockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]domain.UnlockSession
}

var _ app.UnlockSessionStore = (*MemoryUnlockSessionStore)(nil)

func NewMemoryUnlockSessionStore() *MemoryUnlockSessionStore {
	return &MemoryUnlockSessionStore{sessions: map[string]domain.UnlockSession{}}
}

func (s *MemoryUnlockSessionStore) Put(ctx context.Context, session domain.UnlockSession) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryUnlockSessionStore) Get(ctx context.Context, sessionID string) (domain.UnlockSession, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.UnlockSession{}, fmt.Errorf("unlock session not found")
	}
	return session, nil
}

func (s *MemoryUnlockSessionStore) Delete(ctx context.Context, sessionID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}
