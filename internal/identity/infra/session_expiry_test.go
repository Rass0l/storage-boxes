package infra

import (
	"context"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestSessionExpiresAfterIdleTimeout(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)}
	var _ clock.Clock = fc
	store := NewMemorySessionStore(SessionOptions{
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour, Clock: fc,
	})
	sess, err := store.Issue(context.Background(), domain.User{ID: "u1"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Within idle window — should resolve and slide.
	fc.advance(5 * time.Minute)
	if _, err := store.Current(context.Background(), sess.ID); err != nil {
		t.Fatalf("within idle: %v", err)
	}

	// Beyond the *new* sliding deadline — should expire.
	fc.advance(11 * time.Minute)
	if _, err := store.Current(context.Background(), sess.ID); err == nil {
		t.Fatalf("expected expiry")
	}
}

// The sliding deadline must never advance past the absolute deadline. A
// naive implementation would let a heavily-used cookie live forever.
func TestSessionAbsoluteDeadlineCapsSliding(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)}
	store := NewMemorySessionStore(SessionOptions{
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 30 * time.Minute, Clock: fc,
	})
	sess, _ := store.Issue(context.Background(), domain.User{ID: "u1"})

	// Simulate a client that pings /me every 5 minutes. Sliding would keep
	// the session alive indefinitely; absolute must eventually kill it.
	for i := 0; i < 5; i++ {
		fc.advance(5 * time.Minute)
		if _, err := store.Current(context.Background(), sess.ID); err != nil {
			if i < 5 {
				t.Fatalf("step %d: unexpected expiry: %v", i, err)
			}
		}
	}
	// We're now at t0+25min — still within the 30min absolute cap.
	if _, err := store.Current(context.Background(), sess.ID); err != nil {
		t.Fatalf("within absolute: %v", err)
	}
	fc.advance(10 * time.Minute) // push past absolute (t0+35)
	if _, err := store.Current(context.Background(), sess.ID); err == nil {
		t.Fatal("expected session to be past absolute lifetime")
	}
}

func TestSessionSweepRemovesExpiredAndRevoked(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)}
	store := NewMemorySessionStore(SessionOptions{
		IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour, Clock: fc,
	})
	doomed, _ := store.Issue(context.Background(), domain.User{ID: "u2"})
	revoked, _ := store.Issue(context.Background(), domain.User{ID: "u3"})
	_ = store.Revoke(context.Background(), revoked.ID)

	fc.advance(2 * time.Minute)
	// Issue a fresh one after advancing so it outlives the sweep window.
	fresh, _ := store.Issue(context.Background(), domain.User{ID: "u1"})

	removed := store.Sweep(fc.t)
	if removed != 2 {
		t.Fatalf("expected 2 sweeps, got %d", removed)
	}
	if _, err := store.Current(context.Background(), doomed.ID); err == nil {
		t.Fatal("doomed session should be gone")
	}
	if _, err := store.Current(context.Background(), revoked.ID); err == nil {
		t.Fatal("revoked session should be gone")
	}
	if _, err := store.Current(context.Background(), fresh.ID); err != nil {
		t.Fatalf("fresh session should survive sweep: %v", err)
	}
}
