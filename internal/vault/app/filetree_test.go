package app_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/infra"
)

func buildService(t *testing.T) (*app.Service, string, []byte) {
	t.Helper()
	svc := app.NewService(app.ServiceDeps{
		Boxes:   infra.NewMemoryBoxRepository(),
		Crypto:  infra.NewMemoryCryptoStore(),
		Files:   infra.NewMemoryFileCatalog(),
		Unlocks: infra.NewMemoryUnlockSessionStore(),
		Engine:  infra.NewEncryptedFSBoxEngine(t.TempDir()),
		IDs:     ids.RandomGenerator{},
		Clock:   clock.RealClock{},
	})
	ctx := context.Background()
	box, err := svc.CreateBoxFull(ctx, app.CreateBoxFullInput{
		OwnerUserID: "u1", Name: "b", SizeBytes: 1 << 20, Password: "boxpass1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	unlock, err := svc.UnlockBox(ctx, box.ID, "u1", "boxpass1")
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	uc, ok := svc.UnlockCache().Lookup(unlock.ID)
	if !ok {
		t.Fatal("unlock cache miss")
	}
	return svc, box.ID, uc.BMK
}

func mustDomainErr(t *testing.T, err error, code string) {
	t.Helper()
	var de *platerr.DomainError
	if !errors.As(err, &de) {
		t.Fatalf("expected DomainError, got %T: %v", err, err)
	}
	if de.Code != code {
		t.Fatalf("expected code %q, got %q (%s)", code, de.Code, de.Message)
	}
}

func TestPutFileRequiresParentFolder(t *testing.T) {
	svc, box, key := buildService(t)
	_, err := svc.PutFileWithKey(context.Background(), box, "/missing/file.txt", "text/plain", key, bytes.NewReader([]byte("x")))
	mustDomainErr(t, err, "parent_missing")
}

func TestCreateFolderRequiresParentFolder(t *testing.T) {
	svc, box, _ := buildService(t)
	_, err := svc.CreateFolderAt(context.Background(), box, "/a/b")
	mustDomainErr(t, err, "parent_missing")
}

func TestParentIDIsPopulated(t *testing.T) {
	svc, box, key := buildService(t)
	ctx := context.Background()
	work, err := svc.CreateFolderAt(ctx, box, "/work")
	if err != nil {
		t.Fatalf("folder: %v", err)
	}
	if work.ParentID != nil {
		t.Fatalf("root-level folder should have nil parent_id, got %v", *work.ParentID)
	}
	file, err := svc.PutFileWithKey(ctx, box, "/work/note.txt", "text/plain", key, bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if file.ParentID == nil || *file.ParentID != work.ID {
		t.Fatalf("file parent_id=%v, want %q", file.ParentID, work.ID)
	}
}

func TestRenameFolderCascadesDescendants(t *testing.T) {
	svc, box, key := buildService(t)
	ctx := context.Background()
	if _, err := svc.CreateFolderAt(ctx, box, "/src"); err != nil {
		t.Fatalf("mk src: %v", err)
	}
	if _, err := svc.CreateFolderAt(ctx, box, "/src/inner"); err != nil {
		t.Fatalf("mk src/inner: %v", err)
	}
	if _, err := svc.PutFileWithKey(ctx, box, "/src/inner/deep.txt", "text/plain", key, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("put: %v", err)
	}

	moved, err := svc.MoveByPath(ctx, box, "/src", "/dst")
	if err != nil {
		t.Fatalf("move folder: %v", err)
	}
	if moved.LogicalPath != "/dst" || moved.Name != "dst" {
		t.Fatalf("root not updated: %+v", moved)
	}

	entries, _ := svc.ListFiles(ctx, box)
	paths := map[string]bool{}
	for _, e := range entries {
		paths[e.LogicalPath] = true
	}
	for _, want := range []string{"/dst", "/dst/inner", "/dst/inner/deep.txt"} {
		if !paths[want] {
			t.Fatalf("expected %q in catalog, got %+v", want, paths)
		}
	}
	for p := range paths {
		if strings.HasPrefix(p, "/src") {
			t.Fatalf("stale src path still present: %q", p)
		}
	}
}

func TestMoveFolderIntoItselfRefused(t *testing.T) {
	svc, box, _ := buildService(t)
	ctx := context.Background()
	_, _ = svc.CreateFolderAt(ctx, box, "/a")
	_, err := svc.MoveByPath(ctx, box, "/a", "/a/b")
	mustDomainErr(t, err, "move_into_self")
}

func TestMoveFileKeepsParentIDInSync(t *testing.T) {
	svc, box, key := buildService(t)
	ctx := context.Background()
	_, _ = svc.CreateFolderAt(ctx, box, "/a")
	_, _ = svc.CreateFolderAt(ctx, box, "/b")
	f, err := svc.PutFileWithKey(ctx, box, "/a/f.txt", "text/plain", key, bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if f.ParentID == nil {
		t.Fatal("expected parent_id on file")
	}
	moved, err := svc.MoveByPath(ctx, box, "/a/f.txt", "/b/f.txt")
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if moved.ParentID == nil {
		t.Fatal("moved file lost parent_id")
	}
	if *moved.ParentID == *f.ParentID {
		t.Fatal("moved file's parent_id did not change")
	}
}
