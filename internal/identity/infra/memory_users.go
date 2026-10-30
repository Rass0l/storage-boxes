package infra

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
)

type MemoryUserStore struct {
	mu      sync.RWMutex
	byID    map[string]domain.User
	byEmail map[string]string // lowercased email -> id
}

var _ app.UserStore = (*MemoryUserStore)(nil)

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{byID: map[string]domain.User{}, byEmail: map[string]string{}}
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *MemoryUserStore) Put(ctx context.Context, user domain.User) error {
	_ = ctx
	if user.ID == "" || user.Email == "" {
		return fmt.Errorf("user id and email required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	email := normalizeEmail(user.Email)
	if existing, ok := s.byEmail[email]; ok && existing != user.ID {
		return fmt.Errorf("email already in use")
	}
	s.byID[user.ID] = user
	s.byEmail[email] = user.ID
	return nil
}

func (s *MemoryUserStore) GetByID(ctx context.Context, userID string) (domain.User, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	if !ok {
		return domain.User{}, fmt.Errorf("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byEmail[normalizeEmail(email)]
	if !ok {
		return domain.User{}, fmt.Errorf("user not found")
	}
	u, ok := s.byID[id]
	if !ok {
		return domain.User{}, fmt.Errorf("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) List(ctx context.Context) ([]domain.User, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.User, 0, len(s.byID))
	for _, u := range s.byID {
		out = append(out, u)
	}
	return out, nil
}

type MemoryRoleStore struct {
	mu    sync.RWMutex
	roles map[string]map[string]bool
}

var _ app.RoleStore = (*MemoryRoleStore)(nil)

func NewMemoryRoleStore() *MemoryRoleStore {
	return &MemoryRoleStore{roles: map[string]map[string]bool{}}
}

func (r *MemoryRoleStore) Bind(ctx context.Context, userID, role string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[userID]; !ok {
		r.roles[userID] = map[string]bool{}
	}
	r.roles[userID][role] = true
	return nil
}

func (r *MemoryRoleStore) Unbind(ctx context.Context, userID, role string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.roles[userID]; ok {
		delete(m, role)
	}
	return nil
}

func (r *MemoryRoleStore) RolesFor(ctx context.Context, userID string) ([]string, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	m := r.roles[userID]
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	return out, nil
}

// Ensure MemoryRoleStore also satisfies app.RoleEvaluator.
func (r *MemoryRoleStore) HasRole(ctx context.Context, userID, role string) (bool, error) {
	_ = ctx
	r.mu.RLock()
	defer r.mu.RUnlock()
	if m, ok := r.roles[userID]; ok {
		return m[role], nil
	}
	return false, nil
}
