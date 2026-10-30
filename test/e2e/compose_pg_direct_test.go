//go:build compose_e2e

// Direct Postgres-backed tests that bypass HTTP and talk to the pg stores
// through their own APIs. They require the compose stack to be running
// (or at least Postgres on localhost:5432 with the dev credentials).

package e2e

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	identitydom "github.com/Rass0l/storage-boxes/internal/identity/domain"
	identityinfra "github.com/Rass0l/storage-boxes/internal/identity/infra"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	vaultdom "github.com/Rass0l/storage-boxes/internal/vault/domain"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

const composeDSN = "postgres://postgres:postgres@localhost:5432/storage_boxes?sslmode=disable"

func openPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("COMPOSE_E2E") != "1" {
		t.Skip("set COMPOSE_E2E=1 to run pg-backed tests")
	}
	// Bring stack up; these tests don't reuse the compose stack because they
	// run in isolation under t.TempDir-like semantics (each test namespaces
	// its rows). Use the existing stack helper.
	s := newStack(t)
	s.up()
	t.Cleanup(s.down)

	var pool *pgxpool.Pool
	var err error
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		pool, err = pgxpool.New(context.Background(), composeDSN)
		if err == nil {
			if err = pool.Ping(context.Background()); err == nil {
				t.Cleanup(pool.Close)
				return pool
			}
			pool.Close()
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("could not open pg: %v", err)
	return nil
}

// seedUser inserts a throwaway user so vault rows have a valid owner FK.
func seedUser(t *testing.T, pool *pgxpool.Pool, suffix string) string {
	t.Helper()
	id := "usr_pgdirect_" + suffix
	_, err := pool.Exec(context.Background(), `
		INSERT INTO users(id, email, display_name, status)
		VALUES ($1, $2, 'pg-direct', 'active')
		ON CONFLICT (id) DO NOTHING`,
		id, id+"@example.com")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// TestPGBoxAtomicCreateIsAllOrNothing triggers a transaction failure during
// PutBoxAtomic and verifies that neither the box row nor the crypto
// material row persists.
func TestPGBoxAtomicCreateIsAllOrNothing(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "atomic")
	ctx := context.Background()
	repo := vaultinfra.NewPGBoxRepository(pool)

	box := vaultdom.Box{
		ID: "box_pgatomic", OwnerUserID: userID, Name: "a", SizeBytes: 1024,
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	// First succeeds.
	mat := vaultdom.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: []byte("salt"),
		KDFTime: 1, KDFMemory: 1, KDFThreads: 1,
		CipherAlgo: "aes-256-gcm", Nonce: []byte("n"), WrappedBMK: []byte("w"),
	}
	if err := repo.PutBoxAtomic(ctx, box, mat); err != nil {
		t.Fatalf("initial create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, box.ID)
	})

	// Second call with same box.ID collides on the PK and must leave the
	// DB exactly as-is (no extra crypto row, no partial write).
	before := countCrypto(t, pool, box.ID)
	err := repo.PutBoxAtomic(ctx, box, mat)
	if err == nil {
		t.Fatal("expected PK conflict error on duplicate insert")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected *pgconn.PgError, got %T: %v", err, err)
	}
	after := countCrypto(t, pool, box.ID)
	if before != after {
		t.Fatalf("crypto rows for %s changed across failed insert: before=%d after=%d", box.ID, before, after)
	}
}

func countCrypto(t *testing.T, pool *pgxpool.Pool, boxID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM box_crypto_material WHERE box_id = $1`, boxID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestPGUniquePathConstraint verifies the DB-level UNIQUE (box_id,
// logical_path) index blocks duplicates that somehow slip past the service.
func TestPGUniquePathConstraint(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "unique")
	ctx := context.Background()
	repo := vaultinfra.NewPGBoxRepository(pool)
	files := vaultinfra.NewPGFileCatalog(pool)

	box := vaultdom.Box{ID: "box_uniq", OwnerUserID: userID, Name: "u", SizeBytes: 1024, Status: "active", CreatedAt: time.Now().UTC()}
	if err := repo.PutBoxAtomic(ctx, box, vaultdom.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: []byte("x"),
		CipherAlgo: "aes-256-gcm", Nonce: []byte("n"), WrappedBMK: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, box.ID) })

	now := time.Now().UTC()
	if err := files.PutFileEntry(ctx, vaultdom.FileEntry{
		ID: "fe_first", BoxID: box.ID, LogicalPath: "/dup.txt", Name: "dup.txt",
		ContentType: "text/plain", SizeBytes: 1, CreatedAt: now,
	}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := files.PutFileEntry(ctx, vaultdom.FileEntry{
		ID: "fe_second", BoxID: box.ID, LogicalPath: "/dup.txt", Name: "dup.txt",
		ContentType: "text/plain", SizeBytes: 1, CreatedAt: now,
	})
	if err == nil {
		t.Fatal("expected unique violation on duplicate logical_path")
	}
	if !strings.Contains(err.Error(), "unique") && !strings.Contains(err.Error(), "23505") {
		t.Fatalf("expected unique violation, got: %v", err)
	}
}

// TestPGBoxCascadeCleansVaultTables deletes the owning box and asserts the
// catalog + crypto + unlock rows disappear via ON DELETE CASCADE.
func TestPGBoxCascadeCleansVaultTables(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "cascade")
	ctx := context.Background()
	repo := vaultinfra.NewPGBoxRepository(pool)
	files := vaultinfra.NewPGFileCatalog(pool)
	unlocks := vaultinfra.NewPGUnlockSessionStore(pool)

	box := vaultdom.Box{ID: "box_cascade", OwnerUserID: userID, Name: "c", SizeBytes: 1024, Status: "active", CreatedAt: time.Now().UTC()}
	if err := repo.PutBoxAtomic(ctx, box, vaultdom.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: []byte("x"),
		CipherAlgo: "aes-256-gcm", Nonce: []byte("n"), WrappedBMK: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := files.PutFileEntry(ctx, vaultdom.FileEntry{
		ID: "fe_casc", BoxID: box.ID, LogicalPath: "/a.txt", Name: "a.txt",
		ContentType: "text/plain", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := unlocks.Put(ctx, vaultdom.UnlockSession{
		ID: "ul_casc", BoxID: box.ID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Delete the box; all related rows should cascade away.
	if err := repo.Delete(ctx, box.ID); err != nil {
		t.Fatalf("delete box: %v", err)
	}

	for _, q := range []string{
		"SELECT count(*) FROM box_crypto_material WHERE box_id = 'box_cascade'",
		"SELECT count(*) FROM file_entries WHERE box_id = 'box_cascade'",
		"SELECT count(*) FROM box_unlock_sessions WHERE box_id = 'box_cascade'",
	} {
		var n int
		if err := pool.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("rows not cascaded: %q -> %d", q, n)
		}
	}
}

// TestPGRenameSubtreeIsAtomic builds a folder tree and renames the root,
// asserting every descendant's logical_path moves and no stale rows remain.
// It also verifies that a conflicting row at the destination aborts the
// entire move with no changes.
func TestPGRenameSubtreeIsAtomic(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "rename")
	ctx := context.Background()
	repo := vaultinfra.NewPGBoxRepository(pool)
	files := vaultinfra.NewPGFileCatalog(pool)

	box := vaultdom.Box{ID: "box_rename", OwnerUserID: userID, Name: "r", SizeBytes: 1024, Status: "active", CreatedAt: time.Now().UTC()}
	if err := repo.PutBoxAtomic(ctx, box, vaultdom.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: []byte("x"),
		CipherAlgo: "aes-256-gcm", Nonce: []byte("n"), WrappedBMK: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, box.ID) })

	now := time.Now().UTC()
	mk := func(id, path, kind string, parent *string) {
		ct := "text/plain"
		if kind == "folder" {
			ct = vaultapp_FolderContentType
		}
		if err := files.PutFileEntry(ctx, vaultdom.FileEntry{
			ID: id, BoxID: box.ID, ParentID: parent, LogicalPath: path,
			Name: baseName(path), ContentType: ct, CreatedAt: now,
		}); err != nil {
			t.Fatalf("insert %q: %v", path, err)
		}
	}

	mk("fe_src", "/src", "folder", nil)
	srcID := "fe_src"
	mk("fe_src_inner", "/src/inner", "folder", &srcID)
	innerID := "fe_src_inner"
	mk("fe_src_inner_a", "/src/inner/a.txt", "file", &innerID)
	mk("fe_src_note", "/src/note.txt", "file", &srcID)

	// Successful rename.
	moved, err := files.RenameSubtree(ctx, box.ID, "/src", "/dst", nil)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if moved.LogicalPath != "/dst" {
		t.Fatalf("root logical_path not updated: %+v", moved)
	}

	paths := listPaths(t, pool, box.ID)
	want := map[string]bool{"/dst": true, "/dst/inner": true, "/dst/inner/a.txt": true, "/dst/note.txt": true}
	if len(paths) != len(want) {
		t.Fatalf("descendant count mismatch: got %v want %v", paths, want)
	}
	for p := range want {
		if !paths[p] {
			t.Fatalf("expected %q in catalog, got %v", p, paths)
		}
	}
	for p := range paths {
		if strings.HasPrefix(p, "/src") {
			t.Fatalf("stale /src path in catalog: %q", p)
		}
	}

	// Now attempt a conflicting move: create `/other`, then try to rename
	// /dst into /other/sub when a conflicting blocker exists at that path.
	mk("fe_other", "/other", "folder", nil)
	otherID := "fe_other"
	mk("fe_blocker", "/other/sub", "file", &otherID)
	before := listPaths(t, pool, box.ID)
	_, err = files.RenameSubtree(ctx, box.ID, "/dst", "/other/sub", &otherID)
	if err == nil {
		t.Fatal("expected conflict error when target path exists")
	}
	after := listPaths(t, pool, box.ID)
	if !equalSet(before, after) {
		t.Fatalf("rows changed after failed rename:\nbefore=%v\nafter= %v", before, after)
	}
}

// Inlined locally instead of importing app (which depends on infra and would
// cycle).
const vaultapp_FolderContentType = "inode/directory"

func listPaths(t *testing.T, pool *pgxpool.Pool, boxID string) map[string]bool {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT logical_path FROM file_entries WHERE box_id = $1`, boxID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[p] = true
	}
	return out
}

func equalSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// TestPGDeleteEntryIfEmpty exercises the single-statement folder-safe
// delete. It proves (a) missing path returns a stable sentinel, (b)
// non-empty folders are refused without row changes, and (c) empty folders
// come out cleanly.
func TestPGDeleteEntryIfEmpty(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "delifempty")
	ctx := context.Background()
	repo := vaultinfra.NewPGBoxRepository(pool)
	files := vaultinfra.NewPGFileCatalog(pool)

	box := vaultdom.Box{ID: "box_del_empty", OwnerUserID: userID, Name: "d", SizeBytes: 1024, Status: "active", CreatedAt: time.Now().UTC()}
	if err := repo.PutBoxAtomic(ctx, box, vaultdom.BoxCryptoMaterial{
		BoxID: box.ID, KDFAlgorithm: "argon2id", KDFSalt: []byte("x"),
		CipherAlgo: "aes-256-gcm", Nonce: []byte("n"), WrappedBMK: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, box.ID) })

	now := time.Now().UTC()
	mk := func(id, path, ct string, parent *string) {
		if err := files.PutFileEntry(ctx, vaultdom.FileEntry{
			ID: id, BoxID: box.ID, ParentID: parent, LogicalPath: path,
			Name: baseName(path), ContentType: ct, CreatedAt: now,
		}); err != nil {
			t.Fatalf("insert %q: %v", path, err)
		}
	}
	mk("fe_empty", "/empty", vaultapp_FolderContentType, nil)
	mk("fe_full", "/full", vaultapp_FolderContentType, nil)
	full := "fe_full"
	mk("fe_full_child", "/full/child.txt", "text/plain", &full)

	// (a) missing → "not_found"
	if _, err := files.DeleteEntryIfEmpty(ctx, box.ID, "/nope"); err == nil || err.Error() != "not_found" {
		t.Fatalf("missing path: got %v", err)
	}

	// (b) non-empty → "folder_not_empty"; catalog stays put
	before := listPaths(t, pool, box.ID)
	if _, err := files.DeleteEntryIfEmpty(ctx, box.ID, "/full"); err == nil || err.Error() != "folder_not_empty" {
		t.Fatalf("non-empty folder: got %v", err)
	}
	after := listPaths(t, pool, box.ID)
	if !equalSet(before, after) {
		t.Fatalf("non-empty delete attempted mutated catalog:\nbefore=%v\nafter= %v", before, after)
	}

	// (c) empty → deleted, no remnant row
	deleted, err := files.DeleteEntryIfEmpty(ctx, box.ID, "/empty")
	if err != nil {
		t.Fatalf("empty folder delete: %v", err)
	}
	if deleted.LogicalPath != "/empty" {
		t.Fatalf("unexpected returned entry: %+v", deleted)
	}
	final := listPaths(t, pool, box.ID)
	if final["/empty"] {
		t.Fatalf("row survived delete: %v", final)
	}
}

// TestPGSessionAbsoluteExpirySweep proves Sweep deletes rows past the
// absolute deadline even when the sliding deadline hasn't fired.
func TestPGSessionAbsoluteExpirySweep(t *testing.T) {
	pool := openPG(t)
	userID := seedUser(t, pool, "sweep")
	ctx := context.Background()

	store := identityinfra.NewPGSessionStore(pool, identityinfra.PGSessionOptions{
		IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, Clock: clock.RealClock{},
	})
	sess, err := store.Issue(ctx, identitydom.User{ID: userID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sess.ID) })

	// Force the row into the past via a direct update, then sweep.
	if _, err := pool.Exec(ctx, `
		UPDATE sessions SET absolute_expires_at = now() - INTERVAL '1 minute'
		WHERE id = $1`, sess.ID); err != nil {
		t.Fatal(err)
	}

	removed, err := store.Sweep(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if removed < 1 {
		t.Fatalf("expected at least 1 swept row, got %d", removed)
	}

	if _, err := store.Current(ctx, sess.ID); err == nil {
		t.Fatal("swept session should not resolve")
	} else if !strings.Contains(err.Error(), "not found") && !errors.Is(err, pgx.ErrNoRows) {
		// either "session not found" or pgx.ErrNoRows is acceptable
	}
}
