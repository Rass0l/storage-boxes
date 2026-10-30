//go:build compose_e2e

// Direct Postgres-backed tests for the owner-approved access-request repo
// (migration 017). They bypass HTTP and drive the pg repo APIs against the
// real schema: partial-unique dedupe, the status-guarded Decide, the
// reconcile join queries, ON DELETE CASCADE/SET NULL behavior, and the
// single-statement ReactivateWithPasscode.

package e2e

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// seedRestrictedShare inserts the FK chain a share_access_requests row needs
// (user → box → file → restricted share) plus one active recipient. Returns
// the share id and recipient id. All rows are namespaced by suffix and
// cleaned up.
func seedRestrictedShare(t *testing.T, pool *pgxpool.Pool, suffix string) (shareID, recipientID string) {
	t.Helper()
	ctx := context.Background()
	owner := seedUser(t, pool, "ar_"+suffix)
	boxID := "box_ar_" + suffix
	fileID := "file_ar_" + suffix
	shareID = "shr_ar_" + suffix
	recipientID = "rcp_ar_" + suffix
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed exec: %v", err)
		}
	}
	exec(`INSERT INTO boxes(id,owner_user_id,name,size_bytes,status) VALUES ($1,$2,'ar',1024,'active')`, boxID, owner)
	exec(`INSERT INTO file_entries(id,box_id,kind,logical_path,name) VALUES ($1,$2,'file','/r.txt','r.txt')`, fileID, boxID)
	exec(`INSERT INTO shares(id,box_id,file_entry_id,token_hash,status,access_mode,expires_at,max_downloads)
	      VALUES ($1,$2,$3,$4,'active','restricted',$5,5)`, shareID, boxID, fileID, "tok_"+suffix, time.Now().UTC().Add(time.Hour))
	exec(`INSERT INTO share_recipients(id,share_id,email,email_normalized,passcode_hash,passcode_salt)
	      VALUES ($1,$2,'member@example.com','member@example.com',$3,$4)`, recipientID, shareID, []byte("h"), []byte("s"))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM boxes WHERE id = $1`, boxID) })
	return shareID, recipientID
}

func TestPGAccessRequestLifecycle(t *testing.T) {
	pool := openPG(t)
	ctx := context.Background()
	shareID, recipientID := seedRestrictedShare(t, pool, "life")
	repo := infra.NewPGAccessRequestRepository(pool)
	now := time.Now().UTC()
	exp := now.Add(7 * 24 * time.Hour)

	ar := domain.AccessRequest{
		ID: "areq_life_1", ShareID: shareID, RequesterEmail: "guest@example.com",
		RequesterEmailNormalized: "guest@example.com", RequesterDomain: "example.com",
		Message: "hi", Status: domain.AccessRequestPending, ExpiresAt: &exp,
		RemoteIP: "203.0.113.9", UserAgent: "ua", RiskScore: 3, CountryCode: "US", CreatedAt: now,
	}
	if err := repo.Put(ctx, ar); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Partial unique index: a second pending row for the same (share,email)
	// must violate the constraint.
	dup := ar
	dup.ID = "areq_life_dup"
	if err := repo.Put(ctx, dup); err == nil {
		t.Fatal("duplicate pending insert must violate the partial unique index")
	}

	got, err := repo.Get(ctx, "areq_life_1")
	if err != nil || got.RequesterEmail != "guest@example.com" || got.RiskScore != 3 || got.CountryCode != "US" {
		t.Fatalf("get round-trip mismatch: %+v err=%v", got, err)
	}
	if p, err := repo.GetPendingByShareEmail(ctx, shareID, "guest@example.com"); err != nil || p.ID != "areq_life_1" {
		t.Fatalf("getpending: %+v err=%v", p, err)
	}
	if n, err := repo.CountRecentByShareIP(ctx, shareID, "203.0.113.9", now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("countrecent want 1 got %d err=%v", n, err)
	}

	// ApproveAtomic (New mode): claims the request AND inserts the recipient
	// in one transaction. guest@ is not yet a recipient, so this is a New
	// approval. _ = recipientID (the seeded member@ recipient) is unused here.
	_ = recipientID
	recRepo := infra.NewPGRecipientRepository(pool)
	newRcpID := "rcp_guest_life"
	plan := app.ApprovalPlan{
		RequestID: "areq_life_1", DecidedBy: "u_owner", Reason: domain.AccessReasonOwnerApproved, Now: now,
		Mode: app.ApprovalModeNew,
		Recipient: domain.Recipient{
			ID: newRcpID, ShareID: shareID, Email: "guest@example.com", EmailNormalized: "guest@example.com",
			PasscodeHash: []byte("h"), PasscodeSalt: []byte("s"), CreatedAt: now,
		},
	}
	if err := repo.ApproveAtomic(ctx, plan); err != nil {
		t.Fatalf("approve atomic: %v", err)
	}
	approved, _ := repo.Get(ctx, "areq_life_1")
	if approved.Status != domain.AccessRequestApproved || approved.RecipientID != newRcpID || approved.DecidedBy != "u_owner" || approved.DecidedAt == nil {
		t.Fatalf("approve did not claim+link atomically: %+v", approved)
	}
	// The recipient must exist and be active (written in the same transaction).
	rcp, rerr := recRepo.Get(ctx, newRcpID)
	if rerr != nil || rcp.RevokedAt != nil {
		t.Fatalf("approve did not persist an active recipient: %+v err=%v", rcp, rerr)
	}
	// A second approve on the now-terminal row must lose the claim and write nothing.
	if err := repo.ApproveAtomic(ctx, plan); !errors.Is(err, app.ErrAccessRequestNotPending) {
		t.Fatalf("second approve must report not-pending, got %v", err)
	}
}

// TestPGSupersedeOrphanedApprovals proves the worker's reconcile pass converges
// an approved request whose recipient state is missing (recipient_id NULL).
func TestPGSupersedeOrphanedApprovals(t *testing.T) {
	pool := openPG(t)
	ctx := context.Background()
	shareID, _ := seedRestrictedShare(t, pool, "orphan")
	repo := infra.NewPGAccessRequestRepository(pool)
	now := time.Now().UTC()
	// Seed an approved request with NO recipient link (the inconsistent state).
	if _, err := pool.Exec(ctx, `
		INSERT INTO share_access_requests(id, share_id, requester_email, requester_email_normalized, requester_domain, status)
		VALUES ('areq_orphan', $1, 'ghost@example.com', 'ghost@example.com', 'example.com', 'approved')`, shareID); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}
	changed, err := repo.SupersedeOrphanedApprovals(ctx, now, 100)
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if !containsAR(changed, "areq_orphan") {
		t.Fatalf("orphaned approval not returned by SupersedeOrphanedApprovals: %+v", changed)
	}
	got, _ := repo.Get(ctx, "areq_orphan")
	if got.Status != domain.AccessRequestSuperseded || got.DecisionReason != domain.AccessReasonRecipientMissing {
		t.Fatalf("orphan not superseded(recipient_missing): %s/%s", got.Status, got.DecisionReason)
	}
	// Idempotent: a second pass changes nothing.
	if again, _ := repo.SupersedeOrphanedApprovals(ctx, now, 100); len(again) != 0 {
		t.Fatalf("second supersede pass must be a no-op, got %d", len(again))
	}
}

func TestPGAccessRequestReconcileQueries(t *testing.T) {
	pool := openPG(t)
	ctx := context.Background()
	shareID, _ := seedRestrictedShare(t, pool, "recon")
	repo := infra.NewPGAccessRequestRepository(pool)
	now := time.Now().UTC()

	// Past-TTL pending → ListPendingExpired.
	past := now.Add(-time.Minute)
	mustPut(t, repo, domain.AccessRequest{ID: "areq_recon_ttl", ShareID: shareID, RequesterEmail: "a@example.com",
		RequesterEmailNormalized: "a@example.com", RequesterDomain: "example.com",
		Status: domain.AccessRequestPending, ExpiresAt: &past, CreatedAt: now})
	expired, err := repo.ListPendingExpired(ctx, now, 100)
	if err != nil || !containsAR(expired, "areq_recon_ttl") {
		t.Fatalf("ListPendingExpired missing ttl row: %v", err)
	}

	// Pending mapping to the active recipient → ListPendingWithActiveRecipient.
	mustPut(t, repo, domain.AccessRequest{ID: "areq_recon_moot", ShareID: shareID, RequesterEmail: "member@example.com",
		RequesterEmailNormalized: "member@example.com", RequesterDomain: "example.com",
		Status: domain.AccessRequestPending, CreatedAt: now})
	moot, err := repo.ListPendingWithActiveRecipient(ctx, 100)
	if err != nil || !containsAR(moot, "areq_recon_moot") {
		t.Fatalf("ListPendingWithActiveRecipient missing moot row: %v", err)
	}

	// CASCADE: deleting the share removes its access requests.
	if _, err := pool.Exec(ctx, `DELETE FROM shares WHERE id = $1`, shareID); err != nil {
		t.Fatalf("delete share: %v", err)
	}
	if _, err := repo.Get(ctx, "areq_recon_ttl"); err == nil {
		t.Fatal("access request should cascade-delete with its share")
	}
}

func mustPut(t *testing.T, repo *infra.PGAccessRequestRepository, ar domain.AccessRequest) {
	t.Helper()
	if err := repo.Put(context.Background(), ar); err != nil {
		t.Fatalf("put %s: %v", ar.ID, err)
	}
}

func containsAR(rows []domain.AccessRequest, id string) bool {
	for _, r := range rows {
		if r.ID == id {
			return true
		}
	}
	return false
}

// TestPGRecipientReactivateWithPasscode proves the single-statement
// reactivation clears revoked_at, resets failed_attempts, and rotates the
// passcode atomically.
func TestPGRecipientReactivateWithPasscode(t *testing.T) {
	pool := openPG(t)
	ctx := context.Background()
	_, recipientID := seedRestrictedShare(t, pool, "react")
	recRepo := infra.NewPGRecipientRepository(pool)
	now := time.Now().UTC()

	if err := recRepo.MarkAttempt(ctx, recipientID, false, now); err != nil {
		t.Fatalf("mark attempt: %v", err)
	}
	if err := recRepo.Revoke(ctx, recipientID, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := recRepo.ReactivateWithPasscode(ctx, recipientID, []byte("ns"), []byte("nh"), now); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	rec, err := recRepo.Get(ctx, recipientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.RevokedAt != nil {
		t.Fatal("reactivate must clear revoked_at")
	}
	if rec.FailedAttempts != 0 {
		t.Fatalf("reactivate must reset failed_attempts, got %d", rec.FailedAttempts)
	}
	if string(rec.PasscodeHash) != "nh" || rec.PasscodeRotatedAt == nil {
		t.Fatal("reactivate must rotate the passcode and stamp passcode_rotated_at")
	}
}

// Compile-time guard that the repo satisfies the app interface (matches the
// var _ assertions in infra, kept here so the e2e build also pins it).
var _ app.AccessRequestRepository = (*infra.PGAccessRequestRepository)(nil)
