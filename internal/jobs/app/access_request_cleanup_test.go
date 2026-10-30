package app_test

import (
	"context"
	"testing"
	"time"

	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	jobsapp "github.com/Rass0l/storage-boxes/internal/jobs/app"
	sharesdomain "github.com/Rass0l/storage-boxes/internal/shares/domain"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// buildCleanupFixtures wires an access-request repo with its Shares/Recipients
// reconcile hooks against fresh memory repos, mirroring how cmd/api and the
// worker wire them.
func buildCleanupFixtures() (*sharesinfra.MemoryAccessRequestRepository, *sharesinfra.MemoryShareRepository, *sharesinfra.MemoryRecipientRepository) {
	shares := sharesinfra.NewMemoryShareRepository()
	recipients := sharesinfra.NewMemoryRecipientRepository()
	requests := sharesinfra.NewMemoryAccessRequestRepository()
	requests.Shares = shares
	requests.Recipients = recipients
	return requests, shares, recipients
}

func putPending(t *testing.T, repo *sharesinfra.MemoryAccessRequestRepository, id, shareID, email string, expiresAt *time.Time) {
	t.Helper()
	ar := sharesdomain.AccessRequest{
		ID: id, ShareID: shareID,
		RequesterEmail: email, RequesterEmailNormalized: email, RequesterDomain: "example.com",
		Status: sharesdomain.AccessRequestPending, ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC().Add(-time.Hour),
	}
	if err := repo.Put(context.Background(), ar); err != nil {
		t.Fatalf("put pending %s: %v", id, err)
	}
}

func deliverableShare(id string, expiresAt time.Time) sharesdomain.Share {
	return sharesdomain.Share{ID: id, BoxID: "b", Status: sharesdomain.StatusActive, ExpiresAt: expiresAt}
}

func TestAccessRequestCleanupExpiresPastTTL(t *testing.T) {
	requests, shares, _ := buildCleanupFixtures()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	_ = shares.Put(context.Background(), deliverableShare("s1", now.Add(time.Hour)))
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	putPending(t, requests, "ar_old", "s1", "old@example.com", &past)
	putPending(t, requests, "ar_new", "s1", "new@example.com", &future)

	audit := newAuditAdapter()
	job := jobsapp.AccessRequestCleanupJob{Requests: requests, Audit: audit}
	n, err := job.Run(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 cleaned, got %d", n)
	}
	old, _ := requests.Get(context.Background(), "ar_old")
	if old.Status != sharesdomain.AccessRequestExpired || old.DecisionReason != sharesdomain.AccessReasonExpiredTTL {
		t.Fatalf("ar_old should be expired(ttl), got %s/%s", old.Status, old.DecisionReason)
	}
	fresh, _ := requests.Get(context.Background(), "ar_new")
	if fresh.Status != sharesdomain.AccessRequestPending {
		t.Fatalf("ar_new should stay pending, got %s", fresh.Status)
	}
	if !audit.has(auditdomain.EventShareAccessRequestExpired) {
		t.Fatal("expected access_request_expired audit")
	}
	if !audit.has(auditdomain.EventShareAccessRequestsReconciled) {
		t.Fatal("expected reconciled summary audit")
	}
}

func TestAccessRequestCleanupExpiresOnDeadShare(t *testing.T) {
	requests, shares, _ := buildCleanupFixtures()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// Revoked (non-deliverable) share.
	dead := deliverableShare("s_dead", now.Add(time.Hour))
	dead.Status = sharesdomain.StatusRevoked
	_ = shares.Put(context.Background(), dead)
	future := now.Add(time.Hour)
	putPending(t, requests, "ar_dead", "s_dead", "x@example.com", &future)

	audit := newAuditAdapter()
	job := jobsapp.AccessRequestCleanupJob{Requests: requests, Audit: audit}
	if _, err := job.Run(context.Background(), now, 100); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := requests.Get(context.Background(), "ar_dead")
	if got.Status != sharesdomain.AccessRequestExpired || got.DecisionReason != sharesdomain.AccessReasonShareUnavailable {
		t.Fatalf("want expired(share_unavailable), got %s/%s", got.Status, got.DecisionReason)
	}
}

func TestAccessRequestCleanupSupersedesActiveRecipient(t *testing.T) {
	requests, shares, recipients := buildCleanupFixtures()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	_ = shares.Put(context.Background(), deliverableShare("s1", now.Add(time.Hour)))
	// An active recipient already exists for this (share, email).
	_ = recipients.Put(context.Background(), sharesdomain.Recipient{
		ID: "rcp1", ShareID: "s1", Email: "member@example.com", EmailNormalized: "member@example.com",
		CreatedAt: now.Add(-time.Hour),
	})
	future := now.Add(time.Hour)
	putPending(t, requests, "ar_moot", "s1", "member@example.com", &future)

	audit := newAuditAdapter()
	job := jobsapp.AccessRequestCleanupJob{Requests: requests, Audit: audit}
	n, err := job.Run(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 superseded, got %d", n)
	}
	got, _ := requests.Get(context.Background(), "ar_moot")
	if got.Status != sharesdomain.AccessRequestSuperseded {
		t.Fatalf("want superseded, got %s", got.Status)
	}
	if !audit.has(auditdomain.EventShareAccessRequestSuperseded) {
		t.Fatal("expected access_request_superseded audit")
	}
}

func TestAccessRequestCleanupSupersedesOrphanedApproval(t *testing.T) {
	requests, shares, _ := buildCleanupFixtures()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	_ = shares.Put(context.Background(), deliverableShare("s1", now.Add(time.Hour)))
	// An APPROVED request whose recipient state is missing (recipient_id "").
	// Atomic approval prevents this normally; the worker converges leftovers
	// from restore / migration / out-of-band recipient deletion.
	if err := requests.Put(context.Background(), sharesdomain.AccessRequest{
		ID: "ar_orphan", ShareID: "s1",
		RequesterEmail: "ghost@example.com", RequesterEmailNormalized: "ghost@example.com", RequesterDomain: "example.com",
		Status: sharesdomain.AccessRequestApproved, CreatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}
	audit := newAuditAdapter()
	job := jobsapp.AccessRequestCleanupJob{Requests: requests, Audit: audit}
	n, err := job.Run(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 reconciled, got %d", n)
	}
	got, _ := requests.Get(context.Background(), "ar_orphan")
	if got.Status != sharesdomain.AccessRequestSuperseded || got.DecisionReason != sharesdomain.AccessReasonRecipientMissing {
		t.Fatalf("orphaned approval should be superseded(recipient_missing), got %s/%s", got.Status, got.DecisionReason)
	}
	if !audit.has(auditdomain.EventShareAccessRequestSuperseded) {
		t.Fatal("expected access_request_superseded audit for the orphaned approval")
	}
	// Idempotent: a second run finds nothing (it's now superseded, not approved).
	again, _ := job.Run(context.Background(), now, 100)
	if again != 0 {
		t.Fatalf("second run must be a no-op, got %d", again)
	}
}

func TestAccessRequestCleanupIsIdempotent(t *testing.T) {
	requests, shares, _ := buildCleanupFixtures()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	_ = shares.Put(context.Background(), deliverableShare("s1", now.Add(time.Hour)))
	past := now.Add(-time.Minute)
	putPending(t, requests, "ar_old", "s1", "old@example.com", &past)

	job := jobsapp.AccessRequestCleanupJob{Requests: requests, Audit: newAuditAdapter()}
	first, _ := job.Run(context.Background(), now, 100)
	if first != 1 {
		t.Fatalf("first run want 1, got %d", first)
	}
	// Second run finds nothing pending and must be a clean no-op.
	second, err := job.Run(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second != 0 {
		t.Fatalf("second run want 0 (idempotent), got %d", second)
	}
}
