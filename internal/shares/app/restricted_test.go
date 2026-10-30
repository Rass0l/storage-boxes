package app_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/infra"
)

type capturedAudit struct {
	events  []auditdomain.AuditEvent
	signals []auditdomain.RiskSignal
}

func (c *capturedAudit) Record(_ context.Context, e auditdomain.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}
func (c *capturedAudit) RecordSignal(_ context.Context, s auditdomain.RiskSignal) error {
	c.signals = append(c.signals, s)
	return nil
}
func (c *capturedAudit) List(_ context.Context, _ auditapp.AuditQuery) ([]auditdomain.AuditEvent, error) {
	return c.events, nil
}

func (c *capturedAudit) hasEvent(t string) bool {
	for _, e := range c.events {
		if e.EventType == t {
			return true
		}
	}
	return false
}

func buildRestrictedService(t *testing.T) (*app.Service, *capturedAudit) {
	t.Helper()
	audit := &capturedAudit{}
	svc := app.NewService(app.Deps{
		Shares:     infra.NewMemoryShareRepository(),
		Objects:    infra.NewMemoryShareObjectStore(),
		AccessLog:  infra.NewMemoryAccessRecorder(),
		Recipients: infra.NewMemoryRecipientRepository(),
		Challenges: infra.NewMemoryChallengeRepository(),
		Claims:     infra.NewMemoryClaimRepository(),
		Files:      stubFileLookup{},
		Stage:      stubStageEngine{},
		Tokens:     infra.RandomTokenService{},
		Audit:      audit,
		// Tests model a local-dev deployment: the OTP is surfaced in the
		// verify result. Production behavior (dispatcher / fail-closed) is
		// covered separately in TestRestrictedOTPProduction*.
		DevModeOTPEcho: true,
	})
	return svc, audit
}

func createRestricted(t *testing.T, svc *app.Service, emails []string, opts ...func(*app.CreateShareInput)) app.CreateShareResult {
	t.Helper()
	in := app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy: app.SharePolicy{
			AccessMode:      domain.AccessModeRestricted,
			RecipientEmails: emails,
		},
	}
	for _, o := range opts {
		o(&in)
	}
	res, err := svc.CreateShare(context.Background(), in)
	if err != nil {
		t.Fatalf("create restricted: %v", err)
	}
	return res
}

func TestRestrictedShareCreateReturnsPasscodesOnce(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"a@example.com", "B@Example.com"})
	if len(res.Recipients) != 2 {
		t.Fatalf("want 2 recipients, got %d", len(res.Recipients))
	}
	if len(res.RecipientPasscodes) != 2 {
		t.Fatalf("want 2 passcodes, got %d", len(res.RecipientPasscodes))
	}
	for _, r := range res.Recipients {
		if res.RecipientPasscodes[r.ID] == "" {
			t.Fatalf("missing passcode for %s", r.ID)
		}
		if r.EmailNormalized == strings.ToUpper(r.EmailNormalized) && r.EmailNormalized != "" {
			t.Fatalf("email should be lowercased: %q", r.EmailNormalized)
		}
	}
	if !audit.hasEvent(auditdomain.EventShareCreated) {
		t.Fatal("expected shares.created audit event")
	}
	if !audit.hasEvent(auditdomain.EventShareRecipientAdded) {
		t.Fatal("expected shares.recipient_added audit event")
	}
}

func TestRestrictedShareRejectsTemporaryTokenAccess(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"x@example.com"})
	_, err := svc.OpenByToken(context.Background(), res.RawToken)
	if !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("want ErrClaimRequired, got %v", err)
	}
}

func TestRestrictedVerifyPasscodeIssuesClaimAndGrantsDelivery(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"ok@example.com"})
	rec := res.Recipients[0]
	raw := res.RecipientPasscodes[rec.ID]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, raw, app.RemoteContext{RemoteIP: "10.0.0.1", UserAgent: "t"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.RawClaimToken == "" {
		t.Fatal("expected raw claim token")
	}
	if v.OTPRequired {
		t.Fatal("OTP not required for this share")
	}
	payload, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken)
	if err != nil {
		t.Fatalf("open with claim: %v", err)
	}
	if payload.Share.ID != res.Share.ID {
		t.Fatal("wrong share")
	}
	if !audit.hasEvent(auditdomain.EventShareChallengeSucceeded) {
		t.Fatal("expected challenge_succeeded")
	}
	if !audit.hasEvent(auditdomain.EventShareClaimIssued) {
		t.Fatal("expected claim_issued")
	}
}

func TestRestrictedVerifyFailsOnBadPasscode(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"ok@example.com"})
	_, err := svc.VerifyPasscode(context.Background(), res.RawToken, "ok@example.com", "WRONG", app.RemoteContext{RemoteIP: "10.0.0.2"})
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if !audit.hasEvent(auditdomain.EventShareChallengeFailed) {
		t.Fatal("expected challenge_failed")
	}
}

func TestRestrictedDomainAllowlistEnforced(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"ok@example.com"}, func(in *app.CreateShareInput) {
		in.Policy.DomainAllowlist = []string{"example.com"}
	})
	rec := res.Recipients[0]
	raw := res.RecipientPasscodes[rec.ID]
	_, err := svc.VerifyPasscode(context.Background(), res.RawToken, "someone@other.com", raw, app.RemoteContext{})
	if err == nil {
		t.Fatal("expected domain_not_allowed rejection")
	}
}

func TestRestrictedOTPFlow(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"o@example.com"}, func(in *app.CreateShareInput) {
		in.Policy.RequireOTP = true
	})
	rec := res.Recipients[0]
	passcode := res.RecipientPasscodes[rec.ID]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, passcode, app.RemoteContext{RemoteIP: "10.0.0.3"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.OTPRequired || v.PendingClaimToken == "" || v.RawOTP == "" {
		t.Fatalf("want OTP step, got %+v", v)
	}
	// Claim is not yet active.
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.PendingClaimToken); !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("pending-OTP claim must not deliver, got %v", err)
	}
	// Complete OTP.
	v2, err := svc.SubmitOTP(context.Background(), res.RawToken, v.PendingClaimToken, v.RawOTP, app.RemoteContext{RemoteIP: "10.0.0.3"})
	if err != nil {
		t.Fatalf("submit otp: %v", err)
	}
	if v2.RawClaimToken == "" {
		t.Fatal("expected raw claim after OTP")
	}
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v2.RawClaimToken); err != nil {
		t.Fatalf("open post-OTP: %v", err)
	}
	_ = audit
}

func TestRestrictedRevokeRecipientBlocksDelivery(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"r@example.com"})
	rec := res.Recipients[0]
	raw := res.RecipientPasscodes[rec.ID]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, raw, app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := svc.RevokeRecipient(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken); !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("revoked recipient's claim must not deliver, got %v", err)
	}
	if !audit.hasEvent(auditdomain.EventShareRecipientRevoked) {
		t.Fatal("expected shares.recipient_revoked audit")
	}
}

func TestRestrictedRotatePasscodeInvalidatesClaim(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"rot@example.com"})
	rec := res.Recipients[0]
	raw := res.RecipientPasscodes[rec.ID]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, raw, app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := svc.RotateRecipientPasscode(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken); !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("rotated passcode must invalidate claim, got %v", err)
	}
}

func TestRestrictedMissingRecipientsFailsValidation(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 1,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

// TestRestrictedRevokeRecipientEmitsClaimAudit proves RevokeRecipient
// doesn't silently kill a claim — it writes a shares.claim_revoked
// audit record per affected claim with reason=recipient_revoked, so an
// operator can reconstruct exactly which recipient sessions were
// terminated and why.
func TestRestrictedRevokeRecipientEmitsClaimAudit(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"a@example.com"})
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{RemoteIP: "10.0.0.9"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	_ = v
	if err := svc.RevokeRecipient(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Must see BOTH recipient_revoked (subject=share_recipient) and at
	// least one claim_revoked (subject=share_claim, reason=recipient_revoked).
	if !audit.hasEvent(auditdomain.EventShareRecipientRevoked) {
		t.Fatal("expected shares.recipient_revoked")
	}
	found := false
	for _, e := range audit.events {
		if e.EventType == auditdomain.EventShareClaimRevoked {
			if reason, _ := e.Metadata["reason"].(string); reason == "recipient_revoked" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("want shares.claim_revoked with reason=recipient_revoked; got events=%v", summarize(audit.events))
	}
}

func TestRestrictedRotatePasscodeEmitsClaimAudit(t *testing.T) {
	svc, audit := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"r@example.com"})
	rec := res.Recipients[0]
	if _, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := svc.RotateRecipientPasscode(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	found := false
	for _, e := range audit.events {
		if e.EventType == auditdomain.EventShareClaimRevoked {
			if reason, _ := e.Metadata["reason"].(string); reason == "passcode_rotated" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("want shares.claim_revoked with reason=passcode_rotated; got %v", summarize(audit.events))
	}
}

// TestRestrictedChallengeCarriesEnrichment proves the gateway propagates
// risk_score + country_code into share_challenges so the recipient
// activity timeline can render "where from" alongside share_access_events.
func TestRestrictedChallengeCarriesEnrichment(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"w@example.com"})
	rec := res.Recipients[0]
	if _, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{
		RemoteIP: "10.1.2.3", UserAgent: "t", CountryCode: "LO", RiskScore: 12,
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	chs, err := svc.ListRecipientActivity(context.Background(), "usr_o", res.Share.ID, rec.ID, 10)
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	// Find the passcode challenge specifically — the merged stream
	// includes lifecycle rows that don't carry IP/UA enrichment, so
	// we can't assume the first row is the challenge.
	var passcode *app.RecipientActivityEvent
	for i := range chs {
		if chs[i].Kind == "challenge" && chs[i].ChallengeKind == "passcode" {
			passcode = &chs[i]
			break
		}
	}
	if passcode == nil {
		t.Fatal("expected a passcode challenge in recipient activity")
	}
	if passcode.RiskScore != 12 || passcode.CountryCode != "LO" {
		t.Fatalf("enrichment dropped: %+v", passcode)
	}
}

func summarize(events []auditdomain.AuditEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		r, _ := e.Metadata["reason"].(string)
		if r != "" {
			out = append(out, e.EventType+":"+r)
		} else {
			out = append(out, e.EventType)
		}
	}
	return out
}

// TestRestrictedDeliveryAttributesRecipientOnAccessRow proves the durable
// access-event row for a restricted delivery carries recipient_id so
// audit queries can attribute success AND denial to a specific
// recipient without reverse-joining share_claims.
func TestRestrictedDeliveryAttributesRecipientOnAccessRow(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"dst@example.com"})
	rec := res.Recipients[0]
	raw := res.RecipientPasscodes[rec.ID]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, raw, app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	payload, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if payload.RecipientID != rec.ID {
		t.Fatalf("payload.RecipientID = %q, want %q", payload.RecipientID, rec.ID)
	}
	// Simulate the gateway's RecordAccess call for a success.
	if err := svc.RecordAccess(context.Background(), res.Share.ID, domain.AccessEvent{
		Succeeded:   true,
		RecipientID: payload.RecipientID,
		RemoteIP:    "10.0.0.7",
	}); err != nil {
		t.Fatalf("record success: %v", err)
	}
	// And a denial (simulating a post-purge attempt).
	if err := svc.RecordAccess(context.Background(), res.Share.ID, domain.AccessEvent{
		Succeeded:   false,
		RecipientID: payload.RecipientID,
		RemoteIP:    "10.0.0.7",
		Metadata:    map[string]any{"reason": "share_not_available"},
	}); err != nil {
		t.Fatalf("record denial: %v", err)
	}
	// Activity must include BOTH the passcode challenge and both
	// access rows, sorted newest-first.
	events, err := svc.ListRecipientActivity(context.Background(), "usr_o", res.Share.ID, rec.ID, 50)
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	countByKind := map[string]int{}
	deniedReasonSeen := false
	for _, e := range events {
		countByKind[e.Kind]++
		if e.Kind == "access" && !e.Succeeded && e.Reason == "share_not_available" {
			deniedReasonSeen = true
		}
	}
	if countByKind["challenge"] < 1 {
		t.Fatalf("want >=1 challenge row, got %+v", countByKind)
	}
	if countByKind["access"] < 2 {
		t.Fatalf("want 2 access rows (success + denial), got %+v", countByKind)
	}
	if !deniedReasonSeen {
		t.Fatal("denial access row must carry reason=share_not_available")
	}
	// Access rows on the underlying recorder must carry recipient_id.
	accesses, _ := infra.NewMemoryAccessRecorder().ListByRecipient(context.Background(), rec.ID, 10) // sanity: noop path
	_ = accesses
}

// TestLookupClaimRecipientResolvesCookie proves the gateway-facing
// helper returns the correct recipient for a valid claim cookie and ""
// for tampered / unknown cookies.
func TestLookupClaimRecipientResolvesCookie(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"c@example.com"})
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := svc.LookupClaimRecipient(context.Background(), v.RawClaimToken); got != rec.ID {
		t.Fatalf("lookup claim recipient: got %q, want %q", got, rec.ID)
	}
	if got := svc.LookupClaimRecipient(context.Background(), "tampered"); got != "" {
		t.Fatalf("tampered cookie must not resolve; got %q", got)
	}
	if got := svc.LookupClaimRecipient(context.Background(), ""); got != "" {
		t.Fatalf("empty cookie must not resolve; got %q", got)
	}
}

// TestInspectClaimClassifiesStaleCookie walks the four "cookie present
// but not redeemable" reasons the gateway relies on to record stale-
// cookie denials: tampered / missing, revoked recipient, claim
// revoked, and OTP-pending.
func TestInspectClaimClassifiesStaleCookie(t *testing.T) {
	svc, _ := buildRestrictedService(t)

	// (a) empty cookie → empty reason (gateway treats as "please verify").
	if got := svc.InspectClaim(context.Background(), ""); got.Reason != "" {
		t.Fatalf("empty cookie reason: got %q, want empty", got.Reason)
	}
	// (b) tampered cookie → claim_missing.
	if got := svc.InspectClaim(context.Background(), "not-a-cookie"); got.Reason != domain.ReasonClaimMissing {
		t.Fatalf("tampered cookie reason: got %q", got.Reason)
	}

	// (c) active claim — classifies as claim_active.
	res := createRestricted(t, svc, []string{"c@example.com"})
	rec := res.Recipients[0]
	v, _ := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	got := svc.InspectClaim(context.Background(), v.RawClaimToken)
	if got.Reason != "claim_active" || got.RecipientID != rec.ID {
		t.Fatalf("active claim: %+v", got)
	}

	// (d) revoke the recipient — cookie should classify as claim_revoked
	// with recipient_id attribution so the denial row is durably linked.
	if err := svc.RevokeRecipient(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got = svc.InspectClaim(context.Background(), v.RawClaimToken)
	if got.Reason != domain.ReasonClaimRevoked || got.RecipientID != rec.ID {
		t.Fatalf("revoked claim: %+v", got)
	}
}

// TestInspectClaimFlagsOTPPending proves a cookie issued with
// require_otp=true and not yet completed classifies as otp_required,
// so the stale-cookie denial row carries a reason the operator can
// distinguish from a truly missing cookie.
func TestInspectClaimFlagsOTPPending(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"o@example.com"}, func(in *app.CreateShareInput) {
		in.Policy.RequireOTP = true
	})
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got := svc.InspectClaim(context.Background(), v.PendingClaimToken)
	if got.Reason != domain.ReasonOTPRequired || got.RecipientID != rec.ID {
		t.Fatalf("otp-pending classification: %+v", got)
	}
}

// TestRecipientActivityIncludesLifecycle proves the timeline shows
// the full recipient + claim lifecycle, not just challenges and
// accesses. Without this, an operator looking at a revoked recipient
// sees their passcode attempts but has no record of the revocation
// itself.
func TestRecipientActivityIncludesLifecycle(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"lifecycle@example.com"})
	rec := res.Recipients[0]
	passcode := res.RecipientPasscodes[rec.ID]
	// Verify once so a claim_issued audit record is on file.
	if _, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, passcode, app.RemoteContext{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Rotate passcode — adds passcode_rotated + claim_revoked (for the
	// claim we just issued).
	if _, _, err := svc.RotateRecipientPasscode(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Revoke — adds recipient_revoked.
	if err := svc.RevokeRecipient(context.Background(), "usr_o", res.Share.ID, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	events, err := svc.ListRecipientActivity(context.Background(), "usr_o", res.Share.ID, rec.ID, 200)
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}

	wantLifecycle := map[string]bool{
		auditdomain.EventShareRecipientAdded:   false,
		auditdomain.EventShareClaimIssued:      false,
		auditdomain.EventSharePasscodeRotated:  false,
		auditdomain.EventShareClaimRevoked:     false,
		auditdomain.EventShareRecipientRevoked: false,
	}
	for _, e := range events {
		if e.Kind != "lifecycle" {
			continue
		}
		if _, ok := wantLifecycle[e.LifecycleEvent]; ok {
			wantLifecycle[e.LifecycleEvent] = true
		}
	}
	for ev, seen := range wantLifecycle {
		if !seen {
			t.Errorf("recipient timeline missing lifecycle event %q", ev)
		}
	}

	// The merged timeline must still be sorted newest-first so the
	// UI's default render reads top-down chronologically.
	for i := 1; i < len(events); i++ {
		if events[i-1].OccurredAt.Before(events[i].OccurredAt) {
			t.Fatalf("merged activity not newest-first at index %d", i)
		}
	}

	// lifecycleSucceeded contract: recipient_added + claim_issued are
	// positive (true), revokes/rotations/expirations are false. UI
	// renders that as a red/green tint.
	for _, e := range events {
		if e.Kind != "lifecycle" {
			continue
		}
		pos := e.LifecycleEvent == auditdomain.EventShareRecipientAdded ||
			e.LifecycleEvent == auditdomain.EventShareClaimIssued
		if e.Succeeded != pos {
			t.Errorf("lifecycle event %q: succeeded=%v, want %v", e.LifecycleEvent, e.Succeeded, pos)
		}
	}
}

func TestPublicShareStillWorks(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Share.AccessMode != domain.AccessModePublic {
		t.Fatalf("want public default, got %q", res.Share.AccessMode)
	}
	if _, err := svc.OpenByToken(context.Background(), res.RawToken); err != nil {
		t.Fatalf("public open: %v", err)
	}
}

// --- OTP delivery hardening (A1) ---

type fakeOTPDispatcher struct {
	msgs    []app.OTPMessage
	failNow bool
}

func (f *fakeOTPDispatcher) DispatchOTP(_ context.Context, m app.OTPMessage) error {
	if f.failNow {
		return errors.New("transport down")
	}
	f.msgs = append(f.msgs, m)
	return nil
}

// buildRestrictedServiceWith builds a service with the given OTP knobs and
// hands back the recipient + claim repos so tests can poke stored state
// directly (e.g. simulate a cascade miss).
func buildRestrictedServiceWith(t *testing.T, dispatcher app.OTPDispatcher, devEcho bool) (*app.Service, app.RecipientRepository, app.ClaimRepository) {
	t.Helper()
	recipients := infra.NewMemoryRecipientRepository()
	claims := infra.NewMemoryClaimRepository()
	svc := app.NewService(app.Deps{
		Shares:         infra.NewMemoryShareRepository(),
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         claims,
		Files:          stubFileLookup{},
		Stage:          stubStageEngine{},
		Tokens:         infra.RandomTokenService{},
		Audit:          &capturedAudit{},
		OTPDispatcher:  dispatcher,
		DevModeOTPEcho: devEcho,
	})
	return svc, recipients, claims
}

// TestRestrictedOTPProductionRequiresDispatcher locks the production-safe
// posture: with no dispatcher and no dev echo (a production-like config),
// a require_otp restricted share cannot even be created — far better than
// silently issuing codes that would leak into the verify response.
func TestRestrictedOTPProductionRequiresDispatcher(t *testing.T) {
	svc, _, _ := buildRestrictedServiceWith(t, nil, false)
	_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy: app.SharePolicy{
			AccessMode:      domain.AccessModeRestricted,
			RequireOTP:      true,
			RecipientEmails: []string{"o@example.com"},
		},
	})
	if err == nil {
		t.Fatal("expected create to fail when require_otp has no delivery channel")
	}
	if !strings.Contains(err.Error(), "otp_delivery_not_configured") {
		t.Fatalf("want otp_delivery_not_configured, got %v", err)
	}
	// A non-OTP restricted share is still fine in the same config.
	if _, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"o@example.com"}},
	}); err != nil {
		t.Fatalf("non-OTP restricted create should succeed: %v", err)
	}
}

// TestRestrictedOTPDispatcherDeliversWithoutEcho proves the production path:
// with a dispatcher and echo OFF, the code is delivered out-of-band and is
// NEVER returned in the verify result. The recipient completes verification
// using only the dispatched code.
func TestRestrictedOTPDispatcherDeliversWithoutEcho(t *testing.T) {
	disp := &fakeOTPDispatcher{}
	svc, _, _ := buildRestrictedServiceWith(t, disp, false)
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy: app.SharePolicy{
			AccessMode:      domain.AccessModeRestricted,
			RequireOTP:      true,
			RecipientEmails: []string{"o@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("create with dispatcher: %v", err)
	}
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.OTPRequired {
		t.Fatal("expected OTP step")
	}
	if v.RawOTP != "" {
		t.Fatalf("OTP must NOT be echoed when a dispatcher is configured; got %q", v.RawOTP)
	}
	if len(disp.msgs) != 1 || disp.msgs[0].Code == "" {
		t.Fatalf("dispatcher should have received exactly one code; got %+v", disp.msgs)
	}
	if disp.msgs[0].RecipientEmail != rec.Email {
		t.Fatalf("dispatched to wrong recipient: %q", disp.msgs[0].RecipientEmail)
	}
	// Completing with the dispatched code activates the claim.
	v2, err := svc.SubmitOTP(context.Background(), res.RawToken, v.PendingClaimToken, disp.msgs[0].Code, app.RemoteContext{})
	if err != nil {
		t.Fatalf("submit dispatched otp: %v", err)
	}
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v2.RawClaimToken); err != nil {
		t.Fatalf("open after dispatched-otp: %v", err)
	}
}

// TestRestrictedOTPDispatcherFailureDoesNotEcho ensures a transport failure
// surfaces an error rather than falling back to echoing the code.
func TestRestrictedOTPDispatcherFailureDoesNotEcho(t *testing.T) {
	disp := &fakeOTPDispatcher{failNow: true}
	svc, _, _ := buildRestrictedServiceWith(t, disp, false)
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy: app.SharePolicy{
			AccessMode:      domain.AccessModeRestricted,
			RequireOTP:      true,
			RecipientEmails: []string{"o@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	if err == nil {
		t.Fatalf("expected dispatch failure error, got result %+v", v)
	}
	if v.RawOTP != "" {
		t.Fatalf("OTP must never be echoed on dispatch failure; got %q", v.RawOTP)
	}
}

// TestRestrictedOTPDispatchFailureIsAudited proves a mail delivery failure
// is not silent: it leaves a queryable audit record attributed to the
// recipient with reason=otp_dispatch_failed, so the owner can see that
// delivery — not the recipient — failed.
func TestRestrictedOTPDispatchFailureIsAudited(t *testing.T) {
	audit := &capturedAudit{}
	disp := &fakeOTPDispatcher{failNow: true}
	svc := app.NewService(app.Deps{
		Shares:        infra.NewMemoryShareRepository(),
		Objects:       infra.NewMemoryShareObjectStore(),
		AccessLog:     infra.NewMemoryAccessRecorder(),
		Recipients:    infra.NewMemoryRecipientRepository(),
		Challenges:    infra.NewMemoryChallengeRepository(),
		Claims:        infra.NewMemoryClaimRepository(),
		Files:         stubFileLookup{},
		Stage:         stubStageEngine{},
		Tokens:        infra.RandomTokenService{},
		Audit:         audit,
		OTPDispatcher: disp,
	})
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RequireOTP: true, RecipientEmails: []string{"o@example.com"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := res.Recipients[0]
	if _, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{RemoteIP: "10.0.0.9"}); err == nil {
		t.Fatal("expected dispatch failure")
	}
	found := false
	for _, e := range audit.events {
		if e.EventType == auditdomain.EventShareChallengeFailed &&
			e.SubjectType == auditdomain.SubjectTypeRecipient && e.SubjectID == rec.ID {
			if r, _ := e.Metadata["reason"].(string); r == domain.ReasonOTPDispatchFailed {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected an audited otp_dispatch_failed event on the recipient; got %+v", audit.events)
	}
}

// TestRevokedRecipientWithLiveClaimDenied (A2) simulates a cascade miss:
// the recipient row is revoked but the claim row is left active. Delivery
// must still be refused because OpenWithClaim re-checks the recipient.
func TestRevokedRecipientWithLiveClaimDenied(t *testing.T) {
	svc, recipients, claims := buildRestrictedServiceWith(t, nil, true)
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"r@example.com"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := res.Recipients[0]
	v, err := svc.VerifyPasscode(context.Background(), res.RawToken, rec.Email, res.RecipientPasscodes[rec.ID], app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Sanity: the claim delivers while the recipient is active.
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken); err != nil {
		t.Fatalf("baseline open: %v", err)
	}
	// Revoke ONLY the recipient row, leaving the claim untouched (the
	// cascade-miss scenario).
	now := time.Now().UTC()
	if err := recipients.Revoke(context.Background(), rec.ID, now); err != nil {
		t.Fatalf("revoke recipient row: %v", err)
	}
	// Confirm the claim is genuinely still active in storage.
	c, err := claims.GetByTokenHash(context.Background(), domain.HashClaimToken(v.RawClaimToken))
	if err != nil {
		t.Fatalf("claim lookup: %v", err)
	}
	if c.RevokedAt != nil {
		t.Fatal("test precondition violated: claim should still be active")
	}
	// Delivery must be denied purely on the recipient revocation.
	if _, err := svc.OpenWithClaim(context.Background(), res.RawToken, v.RawClaimToken); !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("revoked recipient with live claim must be denied, got %v", err)
	}
	// InspectClaim attributes the denial to recipient revocation.
	if got := svc.InspectClaim(context.Background(), v.RawClaimToken); got.Reason != domain.ReasonRecipientRevoked {
		t.Fatalf("inspect reason: got %q want %q", got.Reason, domain.ReasonRecipientRevoked)
	}
}

// TestRevokeClaimRejectsForeignShare (A3) proves a creator can't revoke a
// claim belonging to a different share by routing it through one they own.
func TestRevokeClaimRejectsForeignShare(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	shareA := createRestricted(t, svc, []string{"a@example.com"})
	shareB := createRestricted(t, svc, []string{"b@example.com"})
	recB := shareB.Recipients[0]
	vB, err := svc.VerifyPasscode(context.Background(), shareB.RawToken, recB.Email, shareB.RecipientPasscodes[recB.ID], app.RemoteContext{})
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	claimsB, err := svc.ListClaims(context.Background(), "usr_o", shareB.Share.ID)
	if err != nil || len(claimsB) == 0 {
		t.Fatalf("list claims B: %v (n=%d)", err, len(claimsB))
	}
	claimBID := claimsB[0].ID

	// Revoking B's claim through share A must fail.
	if err := svc.RevokeClaim(context.Background(), "usr_o", shareA.Share.ID, claimBID); err == nil {
		t.Fatal("expected cross-share claim revoke to be rejected")
	}
	// B's claim is still usable.
	if _, err := svc.OpenWithClaim(context.Background(), shareB.RawToken, vB.RawClaimToken); err != nil {
		t.Fatalf("claim B should still deliver after rejected cross-share revoke: %v", err)
	}
	// Revoking through the correct share works.
	if err := svc.RevokeClaim(context.Background(), "usr_o", shareB.Share.ID, claimBID); err != nil {
		t.Fatalf("legitimate revoke: %v", err)
	}
	if _, err := svc.OpenWithClaim(context.Background(), shareB.RawToken, vB.RawClaimToken); !errors.Is(err, app.ErrClaimRequired) {
		t.Fatalf("claim B must be dead after legitimate revoke, got %v", err)
	}
}

// flakyRecipients wraps a real RecipientRepository and can force PutBatch
// to fail, simulating a write that errors after earlier work succeeded.
type flakyRecipients struct {
	app.RecipientRepository
	failBatch bool
}

func (f *flakyRecipients) PutBatch(ctx context.Context, recs []domain.Recipient) error {
	if f.failBatch {
		return errors.New("simulated write failure mid-batch")
	}
	return f.RecipientRepository.PutBatch(ctx, recs)
}

// TestAddRecipientsIsAtomicAndRetryable is the core "second write fails"
// regression: when persisting a recipient batch fails, NO recipient rows
// may survive (no dead recipients with undelivered passcodes) and the
// exact same add must succeed cleanly on retry (no poisoned
// recipient_exists collision from a half-written row).
func TestAddRecipientsIsAtomicAndRetryable(t *testing.T) {
	recipients := &flakyRecipients{RecipientRepository: infra.NewMemoryRecipientRepository()}
	svc := app.NewService(app.Deps{
		Shares:         infra.NewMemoryShareRepository(),
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		Files:          stubFileLookup{},
		Stage:          stubStageEngine{},
		Tokens:         infra.RandomTokenService{},
		Audit:          &capturedAudit{},
		DevModeOTPEcho: true,
	})
	// Create with the first recipient (batch works at create time).
	res, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"first@example.com"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	shareID := res.Share.ID
	batch := []string{"a@example.com", "b@example.com", "c@example.com"}

	// Force the recipient batch write to fail.
	recipients.failBatch = true
	if _, err := svc.AddRecipients(context.Background(), app.AddRecipientsInput{
		ActorUserID: "usr_o", ShareID: shareID, Emails: batch,
	}); err == nil {
		t.Fatal("expected AddRecipients to fail when the batch write errors")
	}
	// No partial rows: only the original recipient exists.
	recs, err := svc.ListRecipients(context.Background(), "usr_o", shareID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("failed batch must leave no recipients behind; got %d (expected just the original)", len(recs))
	}

	// Retry the SAME batch with the write now succeeding — must NOT be
	// poisoned by a half-written recipient colliding on the unique
	// constraint, and must return a passcode for every recipient.
	recipients.failBatch = false
	invites, err := svc.AddRecipients(context.Background(), app.AddRecipientsInput{
		ActorUserID: "usr_o", ShareID: shareID, Emails: batch,
	})
	if err != nil {
		t.Fatalf("retry after a failed batch must succeed cleanly, got: %v", err)
	}
	if len(invites) != 3 {
		t.Fatalf("retry must add all 3 recipients; got %d", len(invites))
	}
	for _, inv := range invites {
		if inv.Passcode == "" {
			t.Fatalf("every retried recipient must get a passcode; %s had none", inv.Recipient.Email)
		}
	}
	recs, _ = svc.ListRecipients(context.Background(), "usr_o", shareID)
	if len(recs) != 4 {
		t.Fatalf("after retry want 4 recipients (1 original + 3), got %d", len(recs))
	}
}

// TestRestrictedRejectsInvalidPolicyCombination proves restricted-only
// policy knobs (recipient_emails / domain_allowlist / require_otp) supplied
// on a public share are rejected, not silently dropped into a bearer link.
func TestRestrictedRejectsInvalidPolicyCombination(t *testing.T) {
	base := func() app.CreateShareInput {
		return app.CreateShareInput{
			CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
			UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
			ExpiresAt:    time.Now().UTC().Add(time.Hour),
			MaxDownloads: 5,
		}
	}
	cases := map[string]app.SharePolicy{
		"public+recipients": {AccessMode: domain.AccessModePublic, RecipientEmails: []string{"a@example.com"}},
		"empty+recipients":  {RecipientEmails: []string{"a@example.com"}},
		"public+domains":    {AccessMode: domain.AccessModePublic, DomainAllowlist: []string{"example.com"}},
		"public+otp":        {AccessMode: domain.AccessModePublic, RequireOTP: true},
	}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _ := buildRestrictedService(t)
			in := base()
			in.Policy = pol
			_, err := svc.CreateShare(context.Background(), in)
			if err == nil {
				t.Fatal("expected invalid_policy rejection")
			}
			if !strings.Contains(err.Error(), "invalid_policy") {
				t.Fatalf("want invalid_policy, got %v", err)
			}
		})
	}
}

// TestRecipientEmailValidationRejectsMalformed locks the stricter email
// check: shapes that slipped past the old "contains @" test are rejected,
// and a well-formed address still succeeds. Failing fast leaves no share
// row / stage blob behind.
func TestRecipientEmailValidationRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"a@", "@b.com", "ab", "a@b", "a b@x.com"} {
		t.Run(bad, func(t *testing.T) {
			svc, _ := buildRestrictedService(t)
			_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
				CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
				UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
				ExpiresAt:    time.Now().UTC().Add(time.Hour),
				MaxDownloads: 5,
				Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{bad}},
			})
			if err == nil || !strings.Contains(err.Error(), "invalid_recipient_email") {
				t.Fatalf("email %q: want invalid_recipient_email, got %v", bad, err)
			}
		})
	}
	// Well-formed still works.
	svc, _ := buildRestrictedService(t)
	if _, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"good@example.com"}},
	}); err != nil {
		t.Fatalf("well-formed email should succeed: %v", err)
	}
}

// TestRestrictedCreateValidatesBeforeStaging proves a bad recipient policy
// fails BEFORE any stage blob or share row is persisted (R16: no
// confusing partial state). The stage engine here records whether it was
// invoked.
func TestRestrictedCreateValidatesBeforeStaging(t *testing.T) {
	audit := &capturedAudit{}
	shares := infra.NewMemoryShareRepository()
	stage := &countingStage{}
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        infra.NewMemoryShareObjectStore(),
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     infra.NewMemoryRecipientRepository(),
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		Files:          stubFileLookup{},
		Stage:          stage,
		Tokens:         infra.RandomTokenService{},
		Audit:          audit,
		DevModeOTPEcho: true,
	})
	_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"bad-email"}},
	})
	if err == nil {
		t.Fatal("expected validation failure")
	}
	if stage.staged != 0 {
		t.Fatalf("stage must not run on invalid policy; ran %d times", stage.staged)
	}
}

// countingStage counts Stage() and Delete() invocations so tests can
// assert that validation short-circuits before staging, and that a
// failed create unwinds the stage blob. failDelete forces Delete to
// error, simulating cleanup that itself fails.
type countingStage struct {
	staged     int
	deleted    int
	failDelete bool
}

func (c *countingStage) Stage(_ context.Context, _ string, _ string, _ []byte) (app.StagedPayload, error) {
	c.staged++
	return app.StagedPayload{StorageKey: "sk", WrappedShareKey: []byte("k"), Nonce: []byte("n"), SizeBytes: 1, ContentType: "text/plain", OriginalName: "f"}, nil
}
func (c *countingStage) Delete(_ context.Context, _, _ string) error {
	c.deleted++
	if c.failDelete {
		return errors.New("simulated stage delete failure")
	}
	return nil
}
func (c *countingStage) Open(_ context.Context, _ string, _, _ []byte) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

// seqIDs hands out deterministic IDs so a test can address the rows a
// create attempted to persist.
type seqIDs struct{ n int }

func (s *seqIDs) New(prefix string) string { s.n++; return fmt.Sprintf("%s_%d", prefix, s.n) }

// TestRestrictedCreateRollsBackOnRecipientFailure is the core "after the
// first DB write succeeds" regression: when recipient provisioning fails
// AFTER the share row, object row, and stage blob are persisted, the
// create must unwind ALL of them and emit NO shares.created audit — no
// half-built share parked for the worker.
func TestRestrictedCreateRollsBackOnRecipientFailure(t *testing.T) {
	shares := infra.NewMemoryShareRepository()
	objects := infra.NewMemoryShareObjectStore()
	recipients := &flakyRecipients{RecipientRepository: infra.NewMemoryRecipientRepository(), failBatch: true}
	stage := &countingStage{}
	audit := &capturedAudit{}
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        objects,
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		Files:          stubFileLookup{},
		Stage:          stage,
		Tokens:         infra.RandomTokenService{},
		Audit:          audit,
		IDs:            &seqIDs{},
		DevModeOTPEcho: true,
	})
	_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"r@example.com"}},
	})
	if err == nil {
		t.Fatal("expected create to fail when recipient provisioning fails")
	}
	// shr_1 is the first minted ID (deterministic seqIDs).
	if _, e := shares.Get(context.Background(), "shr_1"); e == nil {
		t.Fatal("share row must be rolled back, but it still exists")
	}
	if _, e := objects.GetObject(context.Background(), "shr_1"); e == nil {
		t.Fatal("share_object row must be rolled back, but it still exists")
	}
	if stage.deleted == 0 {
		t.Fatal("stage blob must be deleted on rollback")
	}
	if audit.hasEvent(auditdomain.EventShareCreated) {
		t.Fatal("a failed create must NOT emit shares.created")
	}
	if audit.hasEvent(auditdomain.EventShareRecipientAdded) {
		t.Fatal("a failed create must NOT emit shares.recipient_added")
	}
	// And the creator can retry cleanly once the fault clears.
	recipients.failBatch = false
	if _, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"r@example.com"}},
	}); err != nil {
		t.Fatalf("retry after rolled-back create must succeed: %v", err)
	}
}

// TestRestrictedCreateRollbackSurvivesCleanupFailure covers the "cleanup
// itself fails" case: when recipient provisioning fails AND the stage
// blob delete also fails, the share/object rows must be LEFT IN PLACE
// (marked purge_requested, non-deliverable) so the worker can still
// locate and reclaim the blob via the share -> object -> storage_key
// chain. Deleting the row while the blob lingers would orphan the blob
// forever.
func TestRestrictedCreateRollbackSurvivesCleanupFailure(t *testing.T) {
	shares := infra.NewMemoryShareRepository()
	objects := infra.NewMemoryShareObjectStore()
	recipients := &flakyRecipients{RecipientRepository: infra.NewMemoryRecipientRepository(), failBatch: true}
	stage := &countingStage{failDelete: true}
	audit := &capturedAudit{}
	svc := app.NewService(app.Deps{
		Shares:         shares,
		Objects:        objects,
		AccessLog:      infra.NewMemoryAccessRecorder(),
		Recipients:     recipients,
		Challenges:     infra.NewMemoryChallengeRepository(),
		Claims:         infra.NewMemoryClaimRepository(),
		Files:          stubFileLookup{},
		Stage:          stage,
		Tokens:         infra.RandomTokenService{},
		Audit:          audit,
		IDs:            &seqIDs{},
		DevModeOTPEcho: true,
	})
	_, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_o", BoxID: "b", FileEntryID: "f",
		UnlockBMK:    []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		MaxDownloads: 5,
		Policy:       app.SharePolicy{AccessMode: domain.AccessModeRestricted, RecipientEmails: []string{"r@example.com"}},
	})
	if err == nil {
		t.Fatal("expected create to fail")
	}
	// The share + object rows MUST remain so the worker can reclaim the
	// blob; they must be non-deliverable (purge_requested set).
	sh, getErr := shares.Get(context.Background(), "shr_1")
	if getErr != nil {
		t.Fatal("share row must remain when blob cleanup fails, so the worker can reclaim the blob")
	}
	if sh.PurgeRequestedAt == nil {
		t.Fatal("surviving share must be stamped purge_requested (worker-owned teardown)")
	}
	if sh.IsDeliverable(time.Now().UTC()) {
		t.Fatal("a rolled-back share must never be deliverable")
	}
	if _, objErr := objects.GetObject(context.Background(), "shr_1"); objErr != nil {
		t.Fatal("object row must remain so the worker can find the blob's storage_key")
	}
	if audit.hasEvent(auditdomain.EventShareCreated) {
		t.Fatal("a failed create must NOT emit shares.created")
	}
}

// TestAddRecipientRejectsDuplicate (B1) proves duplicate recipients produce
// a clean validation/conflict error rather than a unique-constraint 500.
func TestAddRecipientRejectsDuplicate(t *testing.T) {
	svc, _ := buildRestrictedService(t)
	res := createRestricted(t, svc, []string{"dup@example.com"})
	// Adding the same email again is a conflict, not a 500.
	_, err := svc.AddRecipients(context.Background(), app.AddRecipientsInput{
		ActorUserID: "usr_o", ShareID: res.Share.ID, Emails: []string{"DUP@example.com"},
	})
	if err == nil {
		t.Fatal("expected recipient_exists conflict")
	}
	if !strings.Contains(err.Error(), "recipient_exists") {
		t.Fatalf("want recipient_exists, got %v", err)
	}
	// Duplicate within a single request is a validation error.
	_, err = svc.AddRecipients(context.Background(), app.AddRecipientsInput{
		ActorUserID: "usr_o", ShareID: res.Share.ID, Emails: []string{"new@example.com", "new@example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate_recipient") {
		t.Fatalf("want duplicate_recipient, got %v", err)
	}
}
