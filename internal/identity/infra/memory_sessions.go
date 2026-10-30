package infra

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
)

type MemorySessionStore struct {
	mu              sync.RWMutex
	sessions        map[string]domain.Session
	clock           clock.Clock
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
}

var _ app.SessionService = (*MemorySessionStore)(nil)

type SessionOptions struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Clock           clock.Clock
}

func NewMemorySessionStore(opts SessionOptions) *MemorySessionStore {
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 24 * time.Hour
	}
	if opts.AbsoluteTimeout <= 0 {
		opts.AbsoluteTimeout = 7 * 24 * time.Hour
	}
	return &MemorySessionStore{
		sessions:        map[string]domain.Session{},
		clock:           opts.Clock,
		idleTimeout:     opts.IdleTimeout,
		absoluteTimeout: opts.AbsoluteTimeout,
	}
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *MemorySessionStore) Issue(ctx context.Context, user domain.User) (domain.Session, error) {
	_ = ctx
	token, err := randomToken(32)
	if err != nil {
		return domain.Session{}, fmt.Errorf("session token: %w", err)
	}
	now := s.clock.Now()
	session := domain.Session{
		ID:                token,
		UserID:            user.ID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(s.idleTimeout),
		AbsoluteExpiresAt: now.Add(s.absoluteTimeout),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = session
	return session, nil
}

// Current returns the session iff it exists, has not been revoked, has not
// exceeded its absolute lifetime, and has not exceeded its sliding idle
// deadline. On success, the idle deadline is bumped forward — but never past
// the absolute deadline — so long-lived clients cannot extend the session
// beyond its original hard cap.
func (s *MemorySessionStore) Current(ctx context.Context, sessionID string) (domain.Session, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.Session{}, fmt.Errorf("session not found")
	}
	if session.RevokedAt != nil {
		return domain.Session{}, fmt.Errorf("session revoked")
	}
	now := s.clock.Now()
	if !session.AbsoluteExpiresAt.IsZero() && !session.AbsoluteExpiresAt.After(now) {
		delete(s.sessions, sessionID)
		return domain.Session{}, fmt.Errorf("session past absolute lifetime")
	}
	if !session.ExpiresAt.After(now) {
		delete(s.sessions, sessionID)
		return domain.Session{}, fmt.Errorf("session idle-expired")
	}
	next := now.Add(s.idleTimeout)
	if !session.AbsoluteExpiresAt.IsZero() && next.After(session.AbsoluteExpiresAt) {
		next = session.AbsoluteExpiresAt
	}
	session.ExpiresAt = next
	s.sessions[sessionID] = session
	return session, nil
}

func (s *MemorySessionStore) Revoke(ctx context.Context, sessionID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	now := s.clock.Now()
	session.RevokedAt = &now
	s.sessions[sessionID] = session
	return nil
}

// Sweep removes sessions that are revoked, idle-expired, or past their
// absolute lifetime.
func (s *MemorySessionStore) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, session := range s.sessions {
		expired := !session.ExpiresAt.After(now) ||
			(!session.AbsoluteExpiresAt.IsZero() && !session.AbsoluteExpiresAt.After(now))
		if session.RevokedAt != nil || expired {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}
