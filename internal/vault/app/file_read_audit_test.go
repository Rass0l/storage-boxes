package app_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestFileReadEmitsAudit proves the `vault.file_read` audit event
// fires after a successful blob open, and does NOT fire when the
// read errors out. Without this, auditing a box unlock would tell you
// the key was issued but not which files the holder actually read.
func TestFileReadEmitsAudit(t *testing.T) {
	captured := &capturingSink{}
	svc := newVaultServiceForAuditTest(t, captured)
	ctx := context.Background()

	box, err := svc.CreateBoxFull(ctx, app.CreateBoxFullInput{
		OwnerUserID: "u", Name: "b", SizeBytes: 1024, Password: "boxpass1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	sess, err := svc.UnlockBox(ctx, box.ID, "u", "boxpass1")
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	uc, err := svc.ResolveUnlock(ctx, sess.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	entry, err := svc.PutFileWithKey(ctx, box.ID, "/read-me.txt", "text/plain", uc.BMK, bytes.NewReader([]byte("payload-bytes")))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	captured.reset()

	// Happy-path read: expect exactly one vault.file_read event keyed
	// to the file.
	entry2, _, err := svc.ReadFileWithKey(ctx, box.ID, entry.ID, uc.BMK)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if entry2.ID != entry.ID {
		t.Fatal("read returned wrong entry")
	}
	if n := captured.countType("vault.file_read"); n != 1 {
		t.Fatalf("expected 1 file_read event, got %d; all=%+v", n, captured.all())
	}

	// Failure read: wrong box id. Must NOT emit file_read.
	captured.reset()
	if _, _, err := svc.ReadFileWithKey(ctx, "wrong_box", entry.ID, uc.BMK); err == nil {
		t.Fatal("expected wrong-box read to fail")
	}
	if n := captured.countType("vault.file_read"); n != 0 {
		t.Fatalf("failed read must not emit file_read; got %d", n)
	}
}

func newVaultServiceForAuditTest(t *testing.T, sink *capturingSink) *app.Service {
	t.Helper()
	svc := app.NewService(app.ServiceDeps{
		Boxes:   infra.NewMemoryBoxRepository(),
		Crypto:  infra.NewMemoryCryptoStore(),
		Files:   infra.NewMemoryFileCatalog(),
		Unlocks: infra.NewMemoryUnlockSessionStore(),
		Engine:  infra.NewEncryptedFSBoxEngine(t.TempDir()),
	})
	svc.SetAuditSink(sink)
	return svc
}

type capturingSink struct {
	mu     sync.Mutex
	events []capturedEvent
}

type capturedEvent struct {
	EventType   string
	SubjectType string
	SubjectID   string
	ActorID     string
	Meta        map[string]any
}

func (s *capturingSink) Emit(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, capturedEvent{eventType, subjectType, subjectID, actorID, meta})
}

func (s *capturingSink) countType(t string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.EventType == t {
			n++
		}
	}
	return n
}

func (s *capturingSink) all() []capturedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]capturedEvent, len(s.events))
	copy(out, s.events)
	return out
}

func (s *capturingSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}
