package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// arHarness bundles a Service wired with an AccessRequestRepository plus
// handles to the underlying memory repos so tests can inspect/mutate state.
type arHarness struct {
	svc        *app.Service
	audit      *capturedAudit
	shares     *infra.MemoryShareRepository
	objects    *infra.MemoryShareObjectStore
	recipients *infra.MemoryRecipientRepository
	requests   *infra.MemoryAccessRequestRepository
}

func buildAccessRequestService(t *testing.T) *arHarness {
	t.Helper()
	audit := &capturedAudit{}
	shares := infra.NewMemoryShareRepository()
	objects := infra.NewMemoryShareObjectStore()
	recipients := infra.NewMemoryRecipientRepository()
	requests := infra.NewMemoryAccessRequestRepository()
	// Wire the reconcile hooks so worker-style queries resolve in memory.
	requests.Recipients = recipients
	requests.Shares = shares
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        objects,
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		AccessRequests: requests,
		Files:          stubFileLookup{},
		Stage:          stubStageEngine{},
		Tokens:         infra.RandomTokenService{},
		Audit:          audit,
		DevModeOTPEcho: true,
	})
	return &arHarness{svc: svc, audit: audit, shares: shares, objects: objects, recipients: recipients, requests: requests}
}

func (h *arHarness) createShare(t *testing.T, emails []string, opts ...func(*app.CreateShareInput)) app.CreateShareResult {
	t.Helper()
	in := app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: emails},
	}
	for _, o := range opts {
		o(&in)
	}
	res, err := h.svc.CreateShare(context.Background(), in)
	if err != nil {
		t.Fatalf("create restricted: %v", err)
	}
	return res
}

func mustErrCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %q, got nil", code)
	}
	if !strings.Contains(err.Error(), code) {
		t.Fatalf("want error containing %q, got %v", code, err)
	}
}

func TestSubmitAccessRequestCreatesPending(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	out, err := h.svc.SubmitAccessRequest(context.Background(), res.RawToken, "New.Person@Example.com", "please let me in", app.RemoteContext{RemoteIP: "203.0.113.9"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.Status != app.PublicStatusPending {
		t.Fatalf("want pending, got %q", out.Status)
	}
	reqs, _ := h.svc.ListAccessRequests(context.Background(), "usr_o", res.Share.ID, "", 100)
	if len(reqs) != 1 {
		t.Fatalf("want 1 stored request, got %d", len(reqs))
	}
	got := reqs[0]
	if got.Status != domain.AccessRequestPending {
		t.Fatalf("want pending status, got %q", got.Status)
	}
	if got.RequesterEmailNormalized != "new.person@example.com" {
		t.Fatalf("email not normalized: %q", got.RequesterEmailNormalized)
	}
	if got.RequesterDomain != "example.com" {
		t.Fatalf("domain not derived: %q", got.RequesterDomain)
	}
	if got.Message != "please let me in" {
		t.Fatalf("message not stored: %q", got.Message)
	}
	if got.ExpiresAt == nil {
		t.Fatal("pending request must carry an expiry")
	}
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequested) {
		t.Fatal("expected shares.access_requested audit event")
	}
}

func TestSubmitAccessRequestRejectsInvalidEmail(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	for _, bad := range []string{"", "nope", "a@b", "a@", "@b.com"} {
		_, err := h.svc.SubmitAccessRequest(context.Background(), res.RawToken, bad, "", app.RemoteContext{})
		mustErrCode(t, err, "invalid_requester_email")
	}
}

func TestSubmitAccessRequestDomainConflict(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"a@corp.com"}, func(in *app.CreateShareInput) {
		in.Policy.DomainAllowlist = []string{"corp.com"}
	})
	_, err := h.svc.SubmitAccessRequest(context.Background(), res.RawToken, "intruder@evil.com", "", app.RemoteContext{})
	mustErrCode(t, err, "domain_not_allowed")
	// No row should be created for an un-approvable request.
	reqs, _ := h.svc.ListAccessRequests(context.Background(), "usr_o", res.Share.ID, "", 100)
	if len(reqs) != 0 {
		t.Fatalf("domain-disallowed request must not be stored, got %d", len(reqs))
	}
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequestBlocked) {
		t.Fatal("expected shares.access_request_blocked audit event")
	}
}

func TestSubmitAccessRequestDeadShare(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"a@example.com"})
	if err := h.svc.Revoke(context.Background(), "usr_o", res.Share.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err := h.svc.SubmitAccessRequest(context.Background(), res.RawToken, "new@example.com", "", app.RemoteContext{})
	mustErrCode(t, err, "share_not_available")
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequestBlocked) {
		t.Fatal("expected blocked audit on dead share")
	}
}

func TestSubmitAccessRequestNonRestricted(t *testing.T) {
	h := buildAccessRequestService(t)
	pub, err := h.svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK: []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), MaxDownloads: 5,
	})
	if err != nil {
		t.Fatalf("create public: %v", err)
	}
	_, err = h.svc.SubmitAccessRequest(context.Background(), pub.RawToken, "x@example.com", "", app.RemoteContext{})
	mustErrCode(t, err, "share_not_restricted")
}

func TestSubmitAccessRequestDuplicatePending(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "dup@example.com", "first", app.RemoteContext{}); err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	out, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "dup@example.com", "second", app.RemoteContext{})
	if err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	if out.Status != app.PublicStatusPending {
		t.Fatalf("duplicate should report pending, got %q", out.Status)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, "", 100)
	if len(reqs) != 1 {
		t.Fatalf("duplicate must not create a second row, got %d", len(reqs))
	}
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequestDuplicate) {
		t.Fatal("expected duplicate audit event")
	}
}

func TestSubmitAccessRequestDuplicateActiveRecipient(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"member@example.com"})
	out, err := h.svc.SubmitAccessRequest(context.Background(), res.RawToken, "member@example.com", "", app.RemoteContext{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.Status != app.PublicStatusRecipientActive {
		t.Fatalf("want recipient_active, got %q", out.Status)
	}
	reqs, _ := h.svc.ListAccessRequests(context.Background(), "usr_o", res.Share.ID, "", 100)
	if len(reqs) != 0 {
		t.Fatalf("active recipient should not create a request row, got %d", len(reqs))
	}
}

func TestSubmitAccessRequestRateLimited(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	ip := "198.51.100.7"
	for i := 0; i < 5; i++ {
		email := string(rune('a'+i)) + "@example.com"
		if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, email, "", app.RemoteContext{RemoteIP: ip}); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	_, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "f@example.com", "", app.RemoteContext{RemoteIP: ip})
	mustErrCode(t, err, "rate_limited")
}

func TestApproveAccessRequestProvisionsNewRecipient(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "hi", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if len(reqs) != 1 {
		t.Fatalf("want 1 pending, got %d", len(reqs))
	}
	out, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, reqs[0].ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if out.Passcode == "" {
		t.Fatal("approval of a new recipient must mint a passcode")
	}
	if out.Reactivated {
		t.Fatal("new recipient should not be flagged reactivated")
	}
	if out.Request.Status != domain.AccessRequestApproved || out.Request.RecipientID != out.Recipient.ID {
		t.Fatalf("request not linked to recipient: %+v", out.Request)
	}
	// The link must be PERSISTED (ApproveAtomic claims the request and links
	// the recipient in one transaction) — re-read from storage to prove it.
	approved, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestApproved, 100)
	if len(approved) != 1 || approved[0].RecipientID != out.Recipient.ID {
		t.Fatalf("approved request did not persist recipient link: %+v", approved)
	}
	// The recipient now exists and can verify with the minted passcode.
	if _, verr := h.svc.VerifyPasscode(ctx, res.RawToken, "guest@example.com", out.Passcode, app.RemoteContext{}); verr != nil {
		t.Fatalf("verify after approval should succeed: %v", verr)
	}
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequestApproved) {
		t.Fatal("expected approved audit event")
	}
	if !h.audit.hasEvent(auditdomain.EventShareRecipientAdded) {
		t.Fatal("expected recipient_added audit event for a new recipient")
	}
}

func TestApproveAccessRequestReactivatesRevokedRecipient(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"returning@example.com"})
	ctx := context.Background()
	rec := res.Recipients[0]
	oldPasscode := res.RecipientPasscodes[rec.ID]
	if err := h.svc.RevokeRecipient(ctx, "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("revoke recipient: %v", err)
	}
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "returning@example.com", "back", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	out, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, reqs[0].ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !out.Reactivated {
		t.Fatal("approval of a revoked recipient must set reactivated")
	}
	if out.Passcode == "" || out.Passcode == oldPasscode {
		t.Fatal("reactivation must mint a fresh passcode")
	}
	if out.Recipient.ID != rec.ID {
		t.Fatalf("reactivation should reuse the same recipient row: %s vs %s", out.Recipient.ID, rec.ID)
	}
	// The OLD passcode must no longer verify; the new one must.
	if _, verr := h.svc.VerifyPasscode(ctx, res.RawToken, "returning@example.com", oldPasscode, app.RemoteContext{}); verr == nil {
		t.Fatal("old passcode must not verify after reactivation")
	}
	if _, verr := h.svc.VerifyPasscode(ctx, res.RawToken, "returning@example.com", out.Passcode, app.RemoteContext{}); verr != nil {
		t.Fatalf("new passcode should verify: %v", verr)
	}
	if !h.audit.hasEvent(auditdomain.EventShareRecipientReactivated) {
		t.Fatal("expected recipient_reactivated audit event")
	}
}

func TestApproveAccessRequestBlockedOnMissingObject(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Simulate a missing staged object.
	if err := h.objects.DeleteObject(ctx, res.Share.ID); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	_, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, reqs[0].ID)
	mustErrCode(t, err, "object_missing")
	// Request stays pending so the owner can retry once fixed.
	again, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if len(again) != 1 {
		t.Fatalf("blocked approval must leave the request pending, got %d", len(again))
	}
}

func TestApproveAccessRequestBlockedOnDeadShare(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if err := h.svc.Revoke(ctx, "usr_o", res.Share.ID); err != nil {
		t.Fatalf("revoke share: %v", err)
	}
	_, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, reqs[0].ID)
	mustErrCode(t, err, "share_not_available")
}

func TestDenyAccessRequestBlocksDelivery(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if err := h.svc.DenyAccessRequest(ctx, "usr_o", res.Share.ID, reqs[0].ID, ""); err != nil {
		t.Fatalf("deny: %v", err)
	}
	// Requester is not a recipient: verification fails.
	if _, verr := h.svc.VerifyPasscode(ctx, res.RawToken, "guest@example.com", "WHATEVER0", app.RemoteContext{}); verr == nil {
		t.Fatal("a denied requester must not be able to verify")
	}
	if !h.audit.hasEvent(auditdomain.EventShareAccessRequestDenied) {
		t.Fatal("expected denied audit event")
	}
}

func TestDecisionIsTerminalIdempotent(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	id := reqs[0].ID
	if _, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, id); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// A second decision on the now-approved request must conflict, not flip it.
	if err := h.svc.DenyAccessRequest(ctx, "usr_o", res.Share.ID, id, ""); err == nil {
		t.Fatal("denying an already-approved request must error")
	}
	// And the repo-level Decide guard returns the sentinel on a lost race.
	if err := h.requests.Decide(ctx, id, domain.AccessRequestSuperseded, "", "", "x", time.Now().UTC()); !errors.Is(err, app.ErrAccessRequestNotPending) {
		t.Fatalf("Decide on a terminal row must return ErrAccessRequestNotPending, got %v", err)
	}
}

func TestAccessRequestStatusMapping(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"member@example.com"})
	ctx := context.Background()
	// Unknown email → none.
	st, err := h.svc.AccessRequestStatus(ctx, res.RawToken, "stranger@example.com")
	if err != nil || st.Status != app.PublicStatusNone {
		t.Fatalf("want none, got %q (%v)", st.Status, err)
	}
	// Active recipient → approved (verify now).
	st, _ = h.svc.AccessRequestStatus(ctx, res.RawToken, "member@example.com")
	if st.Status != app.PublicStatusApproved {
		t.Fatalf("active recipient should map to approved, got %q", st.Status)
	}
	// Pending request → pending.
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	st, _ = h.svc.AccessRequestStatus(ctx, res.RawToken, "guest@example.com")
	if st.Status != app.PublicStatusPending {
		t.Fatalf("want pending, got %q", st.Status)
	}
}

// lostClaimRequests wraps the memory repo but makes the atomic approval claim
// always lose, simulating a concurrent deny / worker expiry / worker supersede
// / second approver that flipped the request out of pending in the window
// between the approve's IsPending read and its claim. Because ApproveAtomic is
// one all-or-nothing operation, returning the lost-race sentinel here means
// NOTHING is written — including no recipient. Every other method delegates to
// the real memory repo so state assertions hold.
type lostClaimRequests struct {
	*infra.MemoryAccessRequestRepository
}

func (l *lostClaimRequests) ApproveAtomic(_ context.Context, _ app.ApprovalPlan) error {
	return app.ErrAccessRequestNotPending
}

// buildLostClaimService wires a service whose access-request claims always
// lose the race, returning the service + the underlying memory repos so a
// test can seed a pending request and inspect recipient state afterward.
func buildLostClaimService(t *testing.T) (*app.Service, *lostClaimRequests, *infra.MemoryRecipientRepository) {
	t.Helper()
	shares := infra.NewMemoryShareRepository()
	recipients := infra.NewMemoryRecipientRepository()
	mem := infra.NewMemoryAccessRequestRepository()
	mem.Recipients = recipients
	mem.Shares = shares
	reqs := &lostClaimRequests{MemoryAccessRequestRepository: mem}
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		AccessRequests: reqs,
		Files:          stubFileLookup{},
		Stage:          stubStageEngine{},
		Tokens:         infra.RandomTokenService{},
		Audit:          &capturedAudit{},
		DevModeOTPEcho: true,
	})
	return svc, reqs, recipients
}

// TestApproveLostClaimRaceDoesNotProvisionRecipient is the core out-of-order
// guarantee for a NEW recipient: if the request is decided by someone else
// between the approve's pending-read and its claim, the approve must NOT have
// created a recipient. Claim-first ordering makes this hold; the old
// recipient-first ordering would strand an active recipient against a
// denied/expired request.
func TestApproveLostClaimRaceDoesNotProvisionRecipient(t *testing.T) {
	svc, reqs, recipients := buildLostClaimService(t)
	res := createRestricted(t, svc, []string{"owner@example.com"})
	ctx := context.Background()
	// Seed a pending request for an email that is NOT yet a recipient.
	if err := reqs.MemoryAccessRequestRepository.Put(ctx, domain.AccessRequest{
		ID: "ar_lost_new", ShareID: res.Share.ID, RequesterEmail: "guest@example.com",
		RequesterEmailNormalized: "guest@example.com", RequesterDomain: "example.com",
		Status: domain.AccessRequestPending, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	_, err := svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, "ar_lost_new")
	mustErrCode(t, err, "access_request_not_pending")
	// CRITICAL: the lost claim must not have created a recipient.
	if _, gerr := recipients.GetByShareEmail(ctx, res.Share.ID, "guest@example.com"); gerr == nil {
		t.Fatal("a lost claim race must NOT provision a recipient")
	}
}

// TestApproveLostClaimRaceDoesNotReactivateRecipient is the same guarantee for
// the REACTIVATION path: a lost claim must leave a previously-revoked
// recipient revoked, with its passcode untouched (no rotation).
func TestApproveLostClaimRaceDoesNotReactivateRecipient(t *testing.T) {
	svc, reqs, recipients := buildLostClaimService(t)
	res := createRestricted(t, svc, []string{"member@example.com"})
	ctx := context.Background()
	rec := res.Recipients[0]
	now := time.Now().UTC()
	if err := recipients.Revoke(ctx, rec.ID, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := reqs.MemoryAccessRequestRepository.Put(ctx, domain.AccessRequest{
		ID: "ar_lost_react", ShareID: res.Share.ID, RequesterEmail: "member@example.com",
		RequesterEmailNormalized: "member@example.com", RequesterDomain: "example.com",
		Status: domain.AccessRequestPending, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	_, err := svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, "ar_lost_react")
	mustErrCode(t, err, "access_request_not_pending")
	got, gerr := recipients.Get(ctx, rec.ID)
	if gerr != nil {
		t.Fatalf("get recipient: %v", gerr)
	}
	if got.RevokedAt == nil {
		t.Fatal("a lost claim race must NOT reactivate the recipient")
	}
	if got.PasscodeRotatedAt != nil {
		t.Fatal("a lost claim race must NOT rotate the recipient passcode")
	}
}

// failPutRecipients makes recipient INSERTs fail, simulating a recipient
// write error inside the atomic approval. Everything else delegates.
type failPutRecipients struct {
	*infra.MemoryRecipientRepository
}

func (f *failPutRecipients) Put(_ context.Context, _ domain.Recipient) error {
	return errors.New("simulated recipient write failure")
}

// TestApproveAtomicRecipientWriteFailureLeavesPending proves the decision is
// all-or-nothing: if the recipient write fails, the request must NOT be
// approved (it stays pending and retryable) and no recipient is created. This
// is the half-applied state the atomic approval eliminates.
func TestApproveAtomicRecipientWriteFailureLeavesPending(t *testing.T) {
	shares := infra.NewMemoryShareRepository()
	recipients := &failPutRecipients{MemoryRecipientRepository: infra.NewMemoryRecipientRepository()}
	mem := infra.NewMemoryAccessRequestRepository()
	mem.Recipients = recipients
	mem.Shares = shares
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		AccessRequests: mem,
		Files:          stubFileLookup{},
		Stage:          stubStageEngine{},
		Tokens:         infra.RandomTokenService{},
		Audit:          &capturedAudit{},
		DevModeOTPEcho: true,
	})
	// Create a restricted share (uses PutBatch, not Put, so create succeeds).
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK: []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), MaxDownloads: 5,
		Policy: app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"owner@example.com"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ctx := context.Background()
	if _, err := svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	pend, _ := svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if len(pend) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pend))
	}
	// Approve: the recipient INSERT fails inside the atomic op.
	if _, err := svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, pend[0].ID); err == nil {
		t.Fatal("approve must fail when the recipient write fails")
	}
	// The request must remain pending (nothing half-applied) ...
	stillPending, _ := svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if len(stillPending) != 1 || stillPending[0].ID != pend[0].ID {
		t.Fatalf("failed approval must leave the request pending, got %+v", stillPending)
	}
	approved, _ := svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestApproved, 100)
	if len(approved) != 0 {
		t.Fatalf("failed approval must not produce an approved row, got %d", len(approved))
	}
	// ... and no recipient for guest@ was created.
	if _, gerr := recipients.GetByShareEmail(ctx, res.Share.ID, "guest@example.com"); gerr == nil {
		t.Fatal("failed approval must not leave a recipient behind")
	}
}

// TestApproveSequentialOutOfOrderKeepsStateConsistent walks the realistic
// owner/worker interleavings that resolve sequentially: a request already
// denied / expired / superseded by another actor cannot then be approved into
// an active recipient. Delivery stays blocked and no recipient is created.
func TestApproveSequentialOutOfOrderKeepsStateConsistent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		decide func(h *arHarness, shareID, reqID string)
	}{
		{"already-denied", func(h *arHarness, shareID, reqID string) {
			_ = h.svc.DenyAccessRequest(context.Background(), "usr_o", shareID, reqID, "")
		}},
		{"already-expired-by-worker", func(h *arHarness, shareID, reqID string) {
			_ = h.requests.Decide(context.Background(), reqID, domain.AccessRequestExpired, "", "", domain.AccessReasonExpiredTTL, time.Now().UTC())
		}},
		{"already-superseded-by-worker", func(h *arHarness, shareID, reqID string) {
			_ = h.requests.Decide(context.Background(), reqID, domain.AccessRequestSuperseded, "", "", domain.AccessReasonRecipientActive, time.Now().UTC())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := buildAccessRequestService(t)
			res := h.createShare(t, []string{"owner@example.com"})
			ctx := context.Background()
			if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
				t.Fatalf("submit: %v", err)
			}
			pend, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
			reqID := pend[0].ID
			// Another actor decides the request first.
			tc.decide(h, res.Share.ID, reqID)
			// The owner's approve must now fail and create no recipient.
			if _, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, reqID); err == nil {
				t.Fatal("approving an already-decided request must fail")
			}
			if _, gerr := h.recipients.GetByShareEmail(ctx, res.Share.ID, "guest@example.com"); gerr == nil {
				t.Fatalf("%s: approve after another decision must not create a recipient", tc.name)
			}
		})
	}
}

// findAudit returns the most recent captured event of a type.
func findAudit(c *capturedAudit, evType string) (auditdomain.AuditEvent, bool) {
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].EventType == evType {
			return c.events[i], true
		}
	}
	return auditdomain.AuditEvent{}, false
}

// TestApproveOldRequestExpiresInsteadOfGranting covers "the request is old":
// a request past its TTL that the worker hasn't swept yet must NOT be approved
// as if fresh. Approval converges it to expired and refuses — no recipient is
// created — and the audit explains it (via=approve).
func TestApproveOldRequestExpiresInsteadOfGranting(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Minute)
	// A pending request whose TTL already lapsed (worker hasn't run).
	if err := h.requests.Put(ctx, domain.AccessRequest{
		ID: "ar_old", ShareID: res.Share.ID,
		RequesterEmail: "old@example.com", RequesterEmailNormalized: "old@example.com", RequesterDomain: "example.com",
		Status: domain.AccessRequestPending, ExpiresAt: &past,
		CreatedAt: time.Now().UTC().Add(-8 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, "ar_old")
	mustErrCode(t, err, "access_request_expired")
	// The request is now terminal (expired), not pending.
	got, _ := h.requests.Get(ctx, "ar_old")
	if got.Status != domain.AccessRequestExpired || got.DecisionReason != domain.AccessReasonExpiredTTL {
		t.Fatalf("old request should be expired(ttl), got %s/%s", got.Status, got.DecisionReason)
	}
	// No recipient was created for the stale request.
	if _, gerr := h.recipients.GetByShareEmail(ctx, res.Share.ID, "old@example.com"); gerr == nil {
		t.Fatal("approving a stale request must NOT create a recipient")
	}
	// Audit explains it: expired, surfaced via the approve attempt.
	ev, ok := findAudit(h.audit, auditdomain.EventShareAccessRequestExpired)
	if !ok || ev.Metadata["via"] != "approve" {
		t.Fatalf("expected access_request_expired audit with via=approve, got %+v", ev.Metadata)
	}
}

// TestApproveLinksRecipientAddedOutOfBand covers "the recipient changed
// elsewhere": between submit and approve the owner added the same email as a
// recipient directly. Approval must LINK (no second recipient, no new
// passcode) and the audit must record recipient_mode=link so the decision is
// self-explanatory.
func TestApproveLinksRecipientAddedOutOfBand(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "later@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Owner adds the recipient out-of-band before deciding the request.
	if _, err := h.svc.AddRecipients(ctx, app.AddRecipientsInput{ActorUserID: "usr_o", ShareID: res.Share.ID, Emails: []string{"later@example.com"}}); err != nil {
		t.Fatalf("add recipients: %v", err)
	}
	pend, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	out, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, pend[0].ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if out.Passcode != "" || out.Reactivated {
		t.Fatalf("linking an already-active recipient must mint no passcode and not reactivate: %+v", out)
	}
	ev, ok := findAudit(h.audit, auditdomain.EventShareAccessRequestApproved)
	if !ok || ev.Metadata["recipient_mode"] != "link" {
		t.Fatalf("approved audit must record recipient_mode=link, got %+v", ev.Metadata)
	}
	// Exactly one recipient row for the email (no duplicate from the request).
	recs, _ := h.svc.ListRecipients(ctx, "usr_o", res.Share.ID)
	n := 0
	for _, r := range recs {
		if r.EmailNormalized == "later@example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 recipient for the email, got %d", n)
	}
}

// TestApproveBlockRecordsOwnerActor covers "the audit trail is the only thing
// explaining the decision": an approve-phase block must attribute the owner
// who attempted it (not look like a system event) and tag phase=approve.
func TestApproveBlockRecordsOwnerActor(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := h.objects.DeleteObject(ctx, res.Share.ID); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	pend, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if _, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, pend[0].ID); err == nil {
		t.Fatal("approve must fail when the staged object is missing")
	}
	ev, ok := findAudit(h.audit, auditdomain.EventShareAccessRequestBlocked)
	if !ok {
		t.Fatal("expected an access_request_blocked audit event")
	}
	if ev.ActorID != "usr_o" {
		t.Fatalf("approve-phase block must record the owner actor, got actor=%q", ev.ActorID)
	}
	if ev.Metadata["phase"] != "approve" || ev.Metadata["reason"] != domain.AccessReasonObjectMissing {
		t.Fatalf("block audit missing phase/reason: %+v", ev.Metadata)
	}
}

// TestApproveDecisionAuditIsSelfExplanatory covers "the audit trail is the
// only thing we have to explain the decision": the single approve event must
// carry who requested (email/domain), from where (origin), how old the request
// was (requested_at), and how policy changed (recipient_mode + recipient_id).
func TestApproveDecisionAuditIsSelfExplanatory(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "hello", app.RemoteContext{RemoteIP: "203.0.113.9", CountryCode: "US"}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	pend, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	if _, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, pend[0].ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ev, ok := findAudit(h.audit, auditdomain.EventShareAccessRequestApproved)
	if !ok {
		t.Fatal("expected approved audit event")
	}
	if ev.ActorID != "usr_o" {
		t.Fatalf("decision must record the deciding owner, got %q", ev.ActorID)
	}
	for _, k := range []string{"requester_email", "requester_domain", "requested_at", "recipient_id", "recipient_mode"} {
		if _, present := ev.Metadata[k]; !present {
			t.Fatalf("approved audit missing %q (not self-explanatory): %+v", k, ev.Metadata)
		}
	}
	if ev.Metadata["requester_remote_ip"] != "203.0.113.9" || ev.Metadata["requester_country"] != "US" {
		t.Fatalf("approved audit must echo the request origin: %+v", ev.Metadata)
	}
	if ev.Metadata["recipient_mode"] != "new" {
		t.Fatalf("first-time approval should be recipient_mode=new, got %v", ev.Metadata["recipient_mode"])
	}
}

// TestPublicStatusReflectsCurrentAccessNotHistory covers the core of "don't
// treat approved as permanent truth": after the recipient an approval created
// is revoked (or goes missing, e.g. after a restore), the PUBLIC status must
// stop reporting `approved` — otherwise the requester is told they still have
// access they no longer have. The request row stays `approved` (history).
func TestPublicStatusReflectsCurrentAccessNotHistory(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	pend, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, domain.AccessRequestPending, 100)
	out, err := h.svc.ApproveAccessRequest(ctx, "usr_o", res.Share.ID, pend[0].ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	// While the recipient is active, the public status is approved (verify now).
	if st, _ := h.svc.AccessRequestStatus(ctx, res.RawToken, "guest@example.com"); st.Status != app.PublicStatusApproved {
		t.Fatalf("active recipient should read approved, got %q", st.Status)
	}
	// Owner revokes the recipient — access is withdrawn.
	if err := h.svc.RevokeRecipient(ctx, "usr_o", res.Share.ID, out.Recipient.ID); err != nil {
		t.Fatalf("revoke recipient: %v", err)
	}
	// The public status must NOT still say approved.
	if st, _ := h.svc.AccessRequestStatus(ctx, res.RawToken, "guest@example.com"); st.Status != app.PublicStatusNone {
		t.Fatalf("after revoke, public status must be none, got %q", st.Status)
	}
	// The request row remains approved (history is preserved for the owner).
	got, _ := h.requests.Get(ctx, pend[0].ID)
	if got.Status != domain.AccessRequestApproved {
		t.Fatalf("request row should stay approved (history), got %q", got.Status)
	}

	// Restore-representative case: the recipient row is gone entirely but the
	// approved request remains. Public status must read none, not approved.
	if err := h.recipients.DeleteByShare(ctx, res.Share.ID); err != nil {
		t.Fatalf("delete recipients: %v", err)
	}
	if st, _ := h.svc.AccessRequestStatus(ctx, res.RawToken, "guest@example.com"); st.Status != app.PublicStatusNone {
		t.Fatalf("missing recipient must read none, got %q", st.Status)
	}
}

func TestAccessRequestOwnershipEnforced(t *testing.T) {
	h := buildAccessRequestService(t)
	res := h.createShare(t, []string{"owner@example.com"})
	ctx := context.Background()
	if _, err := h.svc.SubmitAccessRequest(ctx, res.RawToken, "guest@example.com", "", app.RemoteContext{}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	reqs, _ := h.svc.ListAccessRequests(ctx, "usr_o", res.Share.ID, "", 100)
	// A different user cannot list or approve.
	if _, err := h.svc.ListAccessRequests(ctx, "usr_other", res.Share.ID, "", 100); err == nil {
		t.Fatal("non-owner must not list access requests")
	}
	if _, err := h.svc.ApproveAccessRequest(ctx, "usr_other", res.Share.ID, reqs[0].ID); err == nil {
		t.Fatal("non-owner must not approve access requests")
	}
}
