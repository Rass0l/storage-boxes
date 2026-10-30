package app_test

import (
	"context"
	"testing"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	jobsapp "github.com/Rass0l/storage-boxes/internal/jobs/app"
	sharesdomain "github.com/Rass0l/storage-boxes/internal/shares/domain"
	sharesinfra "github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// audit adapter that satisfies auditapp.AuditService for this test only.
// We capture Record calls; List / RecordSignal are no-ops.
type auditAdapter struct {
	events []auditdomain.AuditEvent
}

func newAuditAdapter() *auditAdapter { return &auditAdapter{} }

func (a *auditAdapter) Record(_ context.Context, e auditdomain.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}
func (a *auditAdapter) RecordSignal(_ context.Context, _ auditdomain.RiskSignal) error { return nil }
func (a *auditAdapter) List(_ context.Context, _ auditapp.AuditQuery) ([]auditdomain.AuditEvent, error) {
	return a.events, nil
}
func (a *auditAdapter) has(t string) bool {
	for _, e := range a.events {
		if e.EventType == t {
			return true
		}
	}
	return false
}
func TestClaimExpiryJobRevokesExpiredClaims(t *testing.T) {
	claims := sharesinfra.NewMemoryClaimRepository()
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	active := sharesdomain.Claim{
		ID: "c_live", ShareID: "s1", RecipientID: "r1",
		TokenHash: sharesdomain.HashClaimToken("a"),
		IssuedAt:  now.Add(-30 * time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	expired := sharesdomain.Claim{
		ID: "c_old", ShareID: "s1", RecipientID: "r1",
		TokenHash: sharesdomain.HashClaimToken("b"),
		IssuedAt:  now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute),
	}
	_ = claims.Put(context.Background(), active)
	_ = claims.Put(context.Background(), expired)

	audit := newAuditAdapter()
	job := jobsapp.ClaimExpiryJob{Claims: claims, Audit: audit}
	n, err := job.Run(context.Background(), now, 10)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 revoked, got %d", n)
	}
	got, _ := claims.Get(context.Background(), "c_old")
	if got.RevokedAt == nil {
		t.Fatal("expired claim should be revoked")
	}
	got2, _ := claims.Get(context.Background(), "c_live")
	if got2.RevokedAt != nil {
		t.Fatal("live claim must not be revoked")
	}
	if !audit.has(auditdomain.EventShareClaimExpired) {
		t.Fatal("expected shares.claim_expired audit event")
	}
}

func TestShareReconciliationRevokesClaimsOnPurgePendingShares(t *testing.T) {
	shares := sharesinfra.NewMemoryShareRepository()
	claims := sharesinfra.NewMemoryClaimRepository()
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	// Share flagged for purge but with an outstanding claim.
	pr := now.Add(-time.Minute)
	_ = shares.Put(context.Background(), sharesdomain.Share{
		ID: "s1", Status: sharesdomain.StatusRevoked, AccessMode: sharesdomain.AccessModeRestricted,
		PurgeRequestedAt: &pr, ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Hour),
	})
	_ = claims.Put(context.Background(), sharesdomain.Claim{
		ID: "c1", ShareID: "s1", RecipientID: "r1",
		TokenHash: sharesdomain.HashClaimToken("x"),
		IssuedAt:  now.Add(-30 * time.Minute), ExpiresAt: now.Add(time.Hour),
	})

	audit := newAuditAdapter()
	job := jobsapp.ShareReconciliationJob{Shares: shares, Claims: claims, Audit: audit}
	n, err := job.Run(context.Background(), now, 10)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 claim revoked, got %d", n)
	}
	got, _ := claims.Get(context.Background(), "c1")
	if got.RevokedAt == nil {
		t.Fatal("claim must be revoked after reconciliation")
	}
	if !audit.has(auditdomain.EventShareReconciled) {
		t.Fatal("expected shares.reconciled audit event")
	}
}

// TestShareReconciliationRevokesClaimsForRevokedRecipient is the
// cascade-miss safety net: a recipient is revoked but a claim it held was
// left active (e.g. the inline cascade was interrupted). The reconciliation
// job must converge it on a still-active share.
func TestShareReconciliationRevokesClaimsForRevokedRecipient(t *testing.T) {
	shares := sharesinfra.NewMemoryShareRepository()
	recipients := sharesinfra.NewMemoryRecipientRepository()
	claims := sharesinfra.NewMemoryClaimRepository()
	// Wire the in-memory recipient join source (PG does this in SQL).
	claims.Recipients = recipients
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	// Active, deliverable share (NOT purge-pending), so only the
	// recipient-revoked path can pick this claim up.
	_ = shares.Put(context.Background(), sharesdomain.Share{
		ID: "s1", Status: sharesdomain.StatusActive, AccessMode: sharesdomain.AccessModeRestricted,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Hour),
	})
	revokedAt := now.Add(-time.Minute)
	_ = recipients.Put(context.Background(), sharesdomain.Recipient{
		ID: "r1", ShareID: "s1", Email: "x@example.com", EmailNormalized: "x@example.com",
		RevokedAt: &revokedAt, CreatedAt: now.Add(-time.Hour),
	})
	// Still-active recipient + claim must be left alone.
	_ = recipients.Put(context.Background(), sharesdomain.Recipient{
		ID: "r2", ShareID: "s1", Email: "y@example.com", EmailNormalized: "y@example.com",
		CreatedAt: now.Add(-time.Hour),
	})
	_ = claims.Put(context.Background(), sharesdomain.Claim{
		ID: "c_orphan", ShareID: "s1", RecipientID: "r1",
		TokenHash: sharesdomain.HashClaimToken("o"),
		IssuedAt:  now.Add(-30 * time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	_ = claims.Put(context.Background(), sharesdomain.Claim{
		ID: "c_ok", ShareID: "s1", RecipientID: "r2",
		TokenHash: sharesdomain.HashClaimToken("k"),
		IssuedAt:  now.Add(-30 * time.Minute), ExpiresAt: now.Add(time.Hour),
	})

	audit := newAuditAdapter()
	job := jobsapp.ShareReconciliationJob{Shares: shares, Claims: claims, Audit: audit}
	n, err := job.Run(context.Background(), now, 10)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 claim revoked (the orphan), got %d", n)
	}
	orphan, _ := claims.Get(context.Background(), "c_orphan")
	if orphan.RevokedAt == nil {
		t.Fatal("orphaned claim of revoked recipient must be revoked")
	}
	ok, _ := claims.Get(context.Background(), "c_ok")
	if ok.RevokedAt != nil {
		t.Fatal("claim of active recipient must NOT be revoked")
	}
	// The per-claim revoke carries the recipient-revoked reconcile reason.
	foundReason := false
	for _, e := range audit.events {
		if e.EventType == auditdomain.EventShareClaimRevoked {
			if r, _ := e.Metadata["reason"].(string); r == "recipient_revoked_reconciled" {
				foundReason = true
			}
		}
	}
	if !foundReason {
		t.Fatal("expected claim_revoked with reason=recipient_revoked_reconciled")
	}
}
