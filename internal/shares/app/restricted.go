package app

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"sort"
	"strings"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// Remote context carried through the verify / claim paths. The gateway
// populates it from the request so every challenge and claim row is tagged
// with the IP / UA / enrichment the audit UI needs.
type RemoteContext struct {
	RemoteIP    string
	UserAgent   string
	Referer     string
	CountryCode string
	RiskScore   int
}

// VerifyResult is what the gateway returns to the recipient after a
// passcode POST. When OTPRequired is true the gateway must prompt for the
// OTP. RawClaimToken is the cookie value to set on the recipient.
//
// RawOTP is a development-only convenience: it is populated only when
// deps.DevModeOTPEcho is true (local dev / tests) and never in
// production-like environments. When deps.OTPDispatcher is configured the
// code is delivered out-of-band and RawOTP stays empty regardless of
// DevModeOTPEcho — the dispatcher is the single channel for the second
// factor.
type VerifyResult struct {
	OTPRequired       bool
	RawClaimToken     string // present when verification is complete (no OTP or OTP already satisfied)
	PendingClaimToken string // present only when OTPRequired: same cookie value, bound to a claim awaiting OTP completion
	RawOTP            string // dev-only surfacing (DevModeOTPEcho); empty in production and whenever an OTPDispatcher is configured
	Recipient         domain.Recipient
	Claim             domain.Claim
}

// AddRecipientsInput adds one or more recipients to an existing restricted
// share. Returns the generated passcodes exactly once.
type AddRecipientsInput struct {
	ActorUserID string
	ShareID     string
	Emails      []string
}

// RecipientInvite bundles a new recipient with its freshly minted raw
// passcode. Passcodes are returned to the creator exactly once; after the
// response is delivered only salt+hash survive in storage.
type RecipientInvite struct {
	Recipient domain.Recipient
	Passcode  string
}

// normalizeRecipientEmails validates and de-duplicates a batch of
// recipient emails against the supplied (already-normalized) domain
// allowlist. It is PURE — no repository access — so callers can validate
// a policy before committing any state (CreateShare validates before
// staging; AddRecipients validates before its persist loop). Rejects
// malformed addresses, domain-disallowed addresses, and in-request
// duplicates; requires at least one recipient.
func normalizeRecipientEmails(allowlist []string, emails []string) ([]string, error) {
	out := make([]string, 0, len(emails))
	seen := map[string]struct{}{}
	for _, raw := range emails {
		norm := domain.NormalizeEmail(raw)
		if norm == "" {
			continue
		}
		if !validRecipientEmail(norm) {
			return nil, platerr.New(platerr.CategoryValidation, "invalid_recipient_email", "invalid recipient email: "+raw)
		}
		if !domain.DomainAllowed(norm, allowlist) {
			return nil, platerr.New(platerr.CategoryValidation, "domain_not_allowed", "recipient "+raw+" is not in the domain allowlist")
		}
		if _, ok := seen[norm]; ok {
			return nil, platerr.New(platerr.CategoryValidation, "duplicate_recipient", "duplicate recipient email in request: "+raw)
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil, platerr.New(platerr.CategoryValidation, "recipients_required", "at least one recipient email is required")
	}
	return out, nil
}

// validRecipientEmail is a pragmatic structural check: a non-empty local
// part, exactly one separating '@', and a domain part with no spaces that
// contains a dot and doesn't start/end with one. It deliberately stays
// lenient (it is not a full RFC 5322 parser) but rejects the malformed
// shapes that slipped through the previous "contains @" check — e.g.
// "a@", "@b", "ab", "a@b" (no dot), "a b@x.com".
func validRecipientEmail(norm string) bool {
	at := strings.IndexByte(norm, '@')
	if at <= 0 || at != strings.LastIndexByte(norm, '@') {
		return false
	}
	local, dom := norm[:at], norm[at+1:]
	if strings.ContainsAny(local, " \t") || strings.ContainsAny(dom, " \t") {
		return false
	}
	if !strings.Contains(dom, ".") || strings.HasPrefix(dom, ".") || strings.HasSuffix(dom, ".") {
		return false
	}
	return true
}

// provisionRecipients persists a PRE-VALIDATED, normalized recipient
// list (see normalizeRecipientEmails) for share, minting a one-shot
// passcode per recipient. The whole batch is written atomically via
// PutBatch: either every recipient row commits or none does. This is the
// fix for the "second write fails" hazard — the previous per-row loop
// could strand committed recipients (with passcodes the caller never
// received, since the function returns no result on error) and poison a
// retry, because the half-written recipient then collides on the
// UNIQUE(share_id, email_normalized) constraint.
//
// Pre-checking existing recipients gives the caller a clean
// recipient_exists error in the common case; the constraint inside
// PutBatch remains the backstop for races (and rolls the batch back).
// Audit events are emitted only AFTER the commit, so a rolled-back batch
// never leaves shares.recipient_added records for rows that don't exist.
func (s *Service) provisionRecipients(ctx context.Context, share domain.Share, normalizedEmails []string, actorID string) ([]domain.Recipient, map[string]string, error) {
	now := s.deps.Clock.Now().UTC()
	recs := make([]domain.Recipient, 0, len(normalizedEmails))
	passcodes := make(map[string]string, len(normalizedEmails))
	for _, email := range normalizedEmails {
		if existing, err := s.deps.Recipients.GetByShareEmail(ctx, share.ID, email); err == nil && existing.ID != "" {
			return nil, nil, platerr.New(platerr.CategoryConflict, "recipient_exists", "recipient already exists for this share: "+email)
		}
		raw, salt := newPasscode()
		rec := domain.Recipient{
			ID:              s.deps.IDs.New("shr_rcp"),
			ShareID:         share.ID,
			Email:           email,
			EmailNormalized: email,
			PasscodeSalt:    salt,
			PasscodeHash:    domain.HashPasscode(salt, []byte(raw)),
			CreatedAt:       now,
		}
		recs = append(recs, rec)
		passcodes[rec.ID] = raw
	}
	if err := s.deps.Recipients.PutBatch(ctx, recs); err != nil {
		return nil, nil, platerr.New(platerr.CategoryInternal, "persist_recipient", err.Error())
	}
	for _, rec := range recs {
		s.emitAudit(ctx, auditdomain.EventShareRecipientAdded, auditdomain.SubjectTypeRecipient, rec.ID, actorID, map[string]any{
			"share_id": share.ID,
			"email":    rec.Email,
		})
	}
	return recs, passcodes, nil
}

// AddRecipients appends more recipients to an existing restricted share.
// The share must be active, restricted, owned by the actor, and not yet
// purged. Returns generated passcodes once.
func (s *Service) AddRecipients(ctx context.Context, in AddRecipientsInput) ([]RecipientInvite, error) {
	share, err := s.Get(ctx, in.ActorUserID, in.ShareID)
	if err != nil {
		return nil, err
	}
	if !share.IsRestricted() {
		return nil, platerr.New(platerr.CategoryConflict, "share_not_restricted", "share is not restricted")
	}
	if share.Status != domain.StatusActive || share.PurgeRequestedAt != nil {
		return nil, platerr.New(platerr.CategoryConflict, "share_not_active", "share is not active")
	}
	normalized, err := normalizeRecipientEmails(share.RecipientDomainAllowlist, in.Emails)
	if err != nil {
		return nil, err
	}
	recs, passcodes, err := s.provisionRecipients(ctx, share, normalized, in.ActorUserID)
	if err != nil {
		return nil, err
	}
	out := make([]RecipientInvite, 0, len(recs))
	for _, r := range recs {
		out = append(out, RecipientInvite{Recipient: r, Passcode: passcodes[r.ID]})
	}
	return out, nil
}

// ListRecipients returns all recipients for a share (creator-only, via Get
// ownership check). Passcode hash/salt are omitted by caller-side DTOs;
// the domain struct still carries them.
func (s *Service) ListRecipients(ctx context.Context, userID, shareID string) ([]domain.Recipient, error) {
	if _, err := s.Get(ctx, userID, shareID); err != nil {
		return nil, err
	}
	return s.deps.Recipients.ListByShare(ctx, shareID)
}

// RotateRecipientPasscode mints a fresh passcode, rewrites salt+hash, and
// returns the raw passcode exactly once. Any outstanding claims for this
// recipient are revoked so they have to re-verify with the new passcode.
func (s *Service) RotateRecipientPasscode(ctx context.Context, userID, shareID, recipientID string) (domain.Recipient, string, error) {
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return domain.Recipient{}, "", err
	}
	rec, err := s.deps.Recipients.Get(ctx, recipientID)
	if err != nil || rec.ShareID != share.ID {
		return domain.Recipient{}, "", platerr.New(platerr.CategoryNotFound, "recipient_not_found", "recipient not found")
	}
	raw, salt := newPasscode()
	hash := domain.HashPasscode(salt, []byte(raw))
	now := s.deps.Clock.Now().UTC()
	if err := s.deps.Recipients.UpdatePasscode(ctx, recipientID, salt, hash, now); err != nil {
		return domain.Recipient{}, "", platerr.New(platerr.CategoryInternal, "persist_rotate", err.Error())
	}
	// Rotating a passcode invalidates any outstanding claims for the
	// recipient. We emit an explicit shares.claim_revoked per claim with
	// reason=passcode_rotated so the audit trail records the terminal
	// transition that the recipient will observe (their cookie stopped
	// working at this moment). Not doing this leaves "recipient
	// revoked" and "claim revoked" indistinguishable in the audit UI.
	s.revokeRecipientClaimsWithAudit(ctx, recipientID, "passcode_rotated", userID, now)
	rec.PasscodeSalt = salt
	rec.PasscodeHash = hash
	rec.PasscodeRotatedAt = &now
	rec.FailedAttempts = 0
	s.emitAudit(ctx, auditdomain.EventSharePasscodeRotated, auditdomain.SubjectTypeRecipient, recipientID, userID, map[string]any{
		"share_id": share.ID,
		"email":    rec.Email,
	})
	return rec, raw, nil
}

// RevokeRecipient stamps revoked_at and revokes any outstanding claims.
// Keeps the row so audit history stays queryable. A shares.claim_revoked
// audit record is emitted per active claim so operators can reconstruct
// exactly which recipient sessions were terminated by this action.
func (s *Service) RevokeRecipient(ctx context.Context, userID, shareID, recipientID string) error {
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return err
	}
	rec, err := s.deps.Recipients.Get(ctx, recipientID)
	if err != nil || rec.ShareID != share.ID {
		return platerr.New(platerr.CategoryNotFound, "recipient_not_found", "recipient not found")
	}
	if rec.RevokedAt != nil {
		return nil
	}
	now := s.deps.Clock.Now().UTC()
	if err := s.deps.Recipients.Revoke(ctx, recipientID, now); err != nil {
		return platerr.New(platerr.CategoryInternal, "persist_revoke_recipient", err.Error())
	}
	s.revokeRecipientClaimsWithAudit(ctx, recipientID, "recipient_revoked", userID, now)
	s.emitAudit(ctx, auditdomain.EventShareRecipientRevoked, auditdomain.SubjectTypeRecipient, recipientID, userID, map[string]any{
		"share_id": share.ID,
		"email":    rec.Email,
	})
	return nil
}

// revokeRecipientClaimsWithAudit revokes every active claim for a
// recipient and emits one shares.claim_revoked audit record per claim
// with the supplied reason. Called from RevokeRecipient and
// RotateRecipientPasscode so the audit log distinguishes
// recipient-revoked claims from passcode-rotated ones from
// TTL-expired ones (ClaimExpiryJob emits shares.claim_expired).
//
// Claim invalidation is the security-critical step and must be all-or-
// nothing: a per-claim revoke loop that skips on error could leave an
// active cookie behind — and for passcode rotation the recipient row
// stays active, so the worker's recipient-revoked reconciliation would
// NOT catch the survivor. We therefore snapshot the claims, then revoke
// them in a single atomic RevokeByRecipient statement, and only then
// emit the per-claim audit detail (best-effort — the security invariant
// no longer depends on it).
func (s *Service) revokeRecipientClaimsWithAudit(ctx context.Context, recipientID, reason, actorID string, now time.Time) {
	claims, listErr := s.deps.Claims.ListByRecipient(ctx, recipientID)
	// Atomic bulk revoke: a single UPDATE flips revoked_at on every claim
	// for this recipient. This is what guarantees no active cookie
	// survives, independent of the audit loop below.
	if err := s.deps.Claims.RevokeByRecipient(ctx, recipientID, now); err != nil {
		return
	}
	if listErr != nil {
		// Cookies are stopped; we just can't enumerate them for the
		// per-claim audit trail this round.
		return
	}
	for _, c := range claims {
		if c.RevokedAt != nil {
			continue // already terminal before this op — not ours to audit
		}
		s.emitAudit(ctx, auditdomain.EventShareClaimRevoked, auditdomain.SubjectTypeClaim, c.ID, actorID, map[string]any{
			"share_id":     c.ShareID,
			"recipient_id": recipientID,
			"reason":       reason,
		})
	}
}

// VerifyPasscode is the recipient-facing entry point from the public
// gateway. It is deliberately conservative on information leakage: a
// passcode miss, a wrong email, a revoked recipient and a domain-disallowed
// email all return the same generic error. The challenge row and audit
// record, however, carry the precise reason so operators can see exactly
// what's happening.
func (s *Service) VerifyPasscode(ctx context.Context, rawToken, email, passcode string, rctx RemoteContext) (VerifyResult, error) {
	share, err := s.ResolveByToken(ctx, rawToken)
	if err != nil {
		return VerifyResult{}, err
	}
	now := s.deps.Clock.Now().UTC()
	if !share.IsDeliverable(now) {
		s.recordChallenge(ctx, share.ID, "", domain.ChallengePasscode, false, domain.ReasonShareNotAvailable, rctx, now, nil)
		return VerifyResult{}, platerr.New(platerr.CategoryNotFound, "share_not_available", "share is not available")
	}
	if !share.IsRestricted() {
		return VerifyResult{}, platerr.New(platerr.CategoryConflict, "share_not_restricted", "share is not restricted")
	}
	// Rate-limit before touching any recipient row so an attacker can't
	// burn through a recipient's FailedAttempts counter from one IP.
	if s.deps.PasscodeRateLimit > 0 {
		failures, _ := s.deps.Challenges.RecentFailures(ctx, share.ID, rctx.RemoteIP, now.Add(-s.deps.PasscodeRateWindow))
		if failures >= s.deps.PasscodeRateLimit {
			s.recordChallenge(ctx, share.ID, "", domain.ChallengePasscode, false, domain.ReasonRateLimited, rctx, now, nil)
			return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "rate_limited", "too many attempts")
		}
	}
	normalized := domain.NormalizeEmail(email)
	if !domain.DomainAllowed(normalized, share.RecipientDomainAllowlist) {
		s.recordChallenge(ctx, share.ID, "", domain.ChallengePasscode, false, domain.ReasonDomainNotAllowed, rctx, now, map[string]any{"email": normalized})
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	rec, err := s.deps.Recipients.GetByShareEmail(ctx, share.ID, normalized)
	if err != nil {
		s.recordChallenge(ctx, share.ID, "", domain.ChallengePasscode, false, domain.ReasonRecipientUnknown, rctx, now, map[string]any{"email": normalized})
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	if rec.RevokedAt != nil {
		s.recordChallenge(ctx, share.ID, rec.ID, domain.ChallengePasscode, false, domain.ReasonRecipientRevoked, rctx, now, nil)
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	if !domain.PasscodeMatches(rec.PasscodeSalt, rec.PasscodeHash, []byte(passcode)) {
		_ = s.deps.Recipients.MarkAttempt(ctx, rec.ID, false, now)
		s.recordChallenge(ctx, share.ID, rec.ID, domain.ChallengePasscode, false, domain.ReasonPasscodeMismatch, rctx, now, nil)
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	_ = s.deps.Recipients.MarkAttempt(ctx, rec.ID, true, now)
	_ = s.deps.Recipients.MarkVerified(ctx, rec.ID, now)
	s.recordChallenge(ctx, share.ID, rec.ID, domain.ChallengePasscode, true, "", rctx, now, nil)
	s.emitAudit(ctx, auditdomain.EventShareChallengeSucceeded, auditdomain.SubjectTypeRecipient, rec.ID, "", map[string]any{
		"share_id":   share.ID,
		"kind":       domain.ChallengePasscode,
		"remote_ip":  rctx.RemoteIP,
		"user_agent": rctx.UserAgent,
		"risk_score": rctx.RiskScore,
	})
	// Issue the claim. For OTP-required shares the claim starts
	// OTPPending=true with an OTP hash; otherwise it is immediately
	// active.
	claim, rawClaim, rawOTP, err := s.newClaim(ctx, share, rec, now, rctx)
	if err != nil {
		return VerifyResult{}, err
	}
	result := VerifyResult{Recipient: rec, Claim: claim}
	if claim.OTPPending {
		result.OTPRequired = true
		result.PendingClaimToken = rawClaim
		// Deliver the second factor over a separate channel (production)
		// or surface it in the response (dev only). A dispatcher error is
		// returned to the caller; the OTP is never echoed as a fallback.
		echo, derr := s.deliverOTP(ctx, share, rec, claim, rawOTP)
		if derr != nil {
			// Make the delivery failure observable to the owner. This is
			// a server-side fault, so it is recorded as an audit event on
			// the recipient (visible on the recipient activity timeline)
			// rather than as a share_challenges row — a challenge row
			// would wrongly count toward the per-IP rate limit and could
			// lock a recipient out during an SMTP outage.
			s.emitAudit(ctx, auditdomain.EventShareChallengeFailed, auditdomain.SubjectTypeRecipient, rec.ID, "", map[string]any{
				"share_id":   share.ID,
				"kind":       domain.ChallengeOTP,
				"reason":     domain.ReasonOTPDispatchFailed,
				"remote_ip":  rctx.RemoteIP,
				"user_agent": rctx.UserAgent,
			})
			return VerifyResult{}, derr
		}
		if echo {
			result.RawOTP = rawOTP
		}
		s.emitAudit(ctx, auditdomain.EventShareChallengeIssued, auditdomain.SubjectTypeRecipient, rec.ID, "", map[string]any{
			"share_id": share.ID,
			"kind":     domain.ChallengeOTP,
			// channel records how the code reached the recipient so the
			// audit trail distinguishes a real out-of-band dispatch from
			// a dev echo. No code material is ever recorded.
			"channel": s.otpChannel(),
		})
	} else {
		result.RawClaimToken = rawClaim
		s.emitAudit(ctx, auditdomain.EventShareClaimIssued, auditdomain.SubjectTypeClaim, claim.ID, "", map[string]any{
			"share_id":     share.ID,
			"recipient_id": rec.ID,
			"expires_at":   claim.ExpiresAt.Format(time.RFC3339),
		})
	}
	return result, nil
}

// SubmitOTP completes the OTP step on a pending claim. The gateway passes
// the claim cookie it issued at passcode time; a correct OTP flips
// OTPPending → false and the claim becomes active.
func (s *Service) SubmitOTP(ctx context.Context, rawToken, rawPendingClaim, otp string, rctx RemoteContext) (VerifyResult, error) {
	share, err := s.ResolveByToken(ctx, rawToken)
	if err != nil {
		return VerifyResult{}, err
	}
	now := s.deps.Clock.Now().UTC()
	if !share.IsDeliverable(now) {
		return VerifyResult{}, platerr.New(platerr.CategoryNotFound, "share_not_available", "share is not available")
	}
	if rawPendingClaim == "" {
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	claim, err := s.deps.Claims.GetByTokenHash(ctx, domain.HashClaimToken(rawPendingClaim))
	if err != nil || claim.ShareID != share.ID {
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	if !claim.OTPPending || claim.RevokedAt != nil {
		return VerifyResult{}, platerr.New(platerr.CategoryConflict, "otp_not_pending", "otp_not_pending")
	}
	if claim.OTPExpiresAt != nil && !claim.OTPExpiresAt.After(now) {
		s.recordChallenge(ctx, share.ID, claim.RecipientID, domain.ChallengeOTP, false, domain.ReasonOTPExpired, rctx, now, nil)
		_ = s.deps.Claims.Revoke(ctx, claim.ID, now)
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "otp expired")
	}
	if len(claim.OTPHash) == 0 || !bytesEqualConst(claim.OTPHash, domain.HashPasscode(claim.TokenHash, []byte(otp))) {
		s.recordChallenge(ctx, share.ID, claim.RecipientID, domain.ChallengeOTP, false, domain.ReasonOTPMismatch, rctx, now, nil)
		return VerifyResult{}, platerr.New(platerr.CategoryAuthz, "verification_failed", "verification failed")
	}
	if err := s.deps.Claims.CompleteOTP(ctx, claim.ID, now); err != nil {
		return VerifyResult{}, platerr.New(platerr.CategoryInternal, "persist_otp", err.Error())
	}
	claim.OTPPending = false
	claim.OTPHash = nil
	claim.OTPExpiresAt = nil
	s.recordChallenge(ctx, share.ID, claim.RecipientID, domain.ChallengeOTP, true, "", rctx, now, nil)
	s.emitAudit(ctx, auditdomain.EventShareChallengeSucceeded, auditdomain.SubjectTypeClaim, claim.ID, "", map[string]any{
		"share_id":     share.ID,
		"recipient_id": claim.RecipientID,
		"kind":         domain.ChallengeOTP,
	})
	s.emitAudit(ctx, auditdomain.EventShareClaimIssued, auditdomain.SubjectTypeClaim, claim.ID, "", map[string]any{
		"share_id":     share.ID,
		"recipient_id": claim.RecipientID,
		"expires_at":   claim.ExpiresAt.Format(time.RFC3339),
	})
	return VerifyResult{RawClaimToken: rawPendingClaim, Claim: claim}, nil
}

// RevokeClaim revokes a single claim. The operation is scoped to shareID:
// the actor must own the share, and the claim must belong to that share.
// This prevents a creator from revoking a claim that belongs to a
// different share by routing it through one they own.
func (s *Service) RevokeClaim(ctx context.Context, actorID, shareID, claimID string) error {
	share, err := s.Get(ctx, actorID, shareID)
	if err != nil {
		return err
	}
	claim, err := s.deps.Claims.Get(ctx, claimID)
	if err != nil || claim.ShareID != share.ID {
		return platerr.New(platerr.CategoryNotFound, "claim_not_found", "claim not found")
	}
	now := s.deps.Clock.Now().UTC()
	if err := s.deps.Claims.Revoke(ctx, claimID, now); err != nil {
		return platerr.New(platerr.CategoryInternal, "persist_revoke_claim", err.Error())
	}
	s.emitAudit(ctx, auditdomain.EventShareClaimRevoked, auditdomain.SubjectTypeClaim, claimID, actorID, map[string]any{
		"share_id":     claim.ShareID,
		"recipient_id": claim.RecipientID,
		"reason":       "operator_revoked",
	})
	return nil
}

// LookupClaimRecipient resolves a raw claim cookie to its recipient_id
// without enforcing IsActive. The gateway uses it on denial paths
// (share_not_available, share_exhausted, stream_interrupted) so the
// durable access row is attributed to the recipient whose cookie was
// in play even when the open failed. Returns "" when the cookie
// doesn't match a known claim (e.g. tampered, claim purged) — the
// gateway falls back to a recipient-less row in that case.
func (s *Service) LookupClaimRecipient(ctx context.Context, rawClaim string) string {
	r := s.InspectClaim(ctx, rawClaim)
	return r.RecipientID
}

// Reasons written on stale-cookie denials so the recipient activity
// row and audit metadata carry the same vocabulary used elsewhere.
// domain.ReasonClaimMissing / ClaimExpired / ClaimRevoked already
// exist; the OTP-pending cookie case reuses ReasonOTPRequired because
// that matches the verify-flow vocabulary (an OTP is required before
// this cookie authorizes a download).

// ClaimLookupResult is what InspectClaim returns. Reason is:
//
//	""              — no cookie was presented (Empty raw claim).
//	claim_missing   — a cookie was presented but doesn't match any
//	                  stored claim (tampered, claim purged).
//	claim_revoked   — claim row exists, revoked_at is set.
//	claim_expired   — claim row exists, expires_at has passed.
//	otp_required    — claim row exists, otp_pending is still true.
//	claim_active    — claim is currently redeemable; caller typically
//	                  will not see this on a denial path.
type ClaimLookupResult struct {
	RecipientID string
	Reason      string
}

// InspectClaim resolves a raw claim cookie to its recipient_id AND
// classifies why a caller might have been denied. Used by the gateway
// on `ErrClaimRequired` so a recipient holding a stale cookie is
// attributed and distinguished from a fresh unverified caller.
// Lookup-only: never mutates state.
func (s *Service) InspectClaim(ctx context.Context, rawClaim string) ClaimLookupResult {
	if rawClaim == "" || s.deps.Claims == nil {
		return ClaimLookupResult{}
	}
	claim, err := s.deps.Claims.GetByTokenHash(ctx, domain.HashClaimToken(rawClaim))
	if err != nil {
		// Cookie was presented but the claim row is unknown.
		return ClaimLookupResult{Reason: domain.ReasonClaimMissing}
	}
	now := s.deps.Clock.Now().UTC()
	switch {
	case claim.RevokedAt != nil:
		return ClaimLookupResult{RecipientID: claim.RecipientID, Reason: domain.ReasonClaimRevoked}
	case !claim.ExpiresAt.IsZero() && !claim.ExpiresAt.After(now):
		return ClaimLookupResult{RecipientID: claim.RecipientID, Reason: domain.ReasonClaimExpired}
	case claim.OTPPending:
		return ClaimLookupResult{RecipientID: claim.RecipientID, Reason: domain.ReasonOTPRequired}
	}
	// The claim itself is redeemable; check the standing authorization
	// behind it. A revoked recipient with a not-yet-cascaded claim is
	// denied by OpenWithClaim, so classify it here too rather than
	// reporting a misleading "claim_active" on the denial path.
	if s.deps.Recipients != nil {
		if rec, err := s.deps.Recipients.Get(ctx, claim.RecipientID); err == nil && rec.RevokedAt != nil {
			return ClaimLookupResult{RecipientID: claim.RecipientID, Reason: domain.ReasonRecipientRevoked}
		}
	}
	return ClaimLookupResult{RecipientID: claim.RecipientID, Reason: "claim_active"}
}

// ListChallenges returns recent verification attempts on a share (creator
// inspection).
func (s *Service) ListChallenges(ctx context.Context, userID, shareID string, limit int) ([]domain.Challenge, error) {
	if _, err := s.Get(ctx, userID, shareID); err != nil {
		return nil, err
	}
	return s.deps.Challenges.ListByShare(ctx, shareID, limit)
}

// ListClaims returns current/past claims for a share.
func (s *Service) ListClaims(ctx context.Context, userID, shareID string) ([]domain.Claim, error) {
	if _, err := s.Get(ctx, userID, shareID); err != nil {
		return nil, err
	}
	return s.deps.Claims.ListByShare(ctx, shareID)
}

// RecipientActivityEvent is one row of the merged recipient timeline.
// Kind is one of:
//
//	"challenge"  — verification attempts (share_challenges)
//	"access"     — restricted-delivery rows (share_access_events)
//	"lifecycle"  — recipient/claim-lifecycle audit events
//	                (shares.recipient_added|_revoked|_passcode_rotated,
//	                 shares.claim_issued|_revoked|_expired)
//
// All three carry the same enrichment fields where available so the UI
// can render them in a single table sorted by OccurredAt. A
// "lifecycle" row has no IP/UA/country enrichment (the creator's
// action is recorded with its actor_id instead).
type RecipientActivityEvent struct {
	Kind        string
	ID          string
	ShareID     string
	RecipientID string
	OccurredAt  time.Time
	Succeeded   bool
	// Reason is populated for challenges (ReasonPasscodeMismatch, etc.)
	// and for denied accesses (from metadata.reason — share_exhausted,
	// stream_interrupted, share_not_available, claim_required, …).
	// Empty for successful accesses and for lifecycle rows.
	Reason string
	// ChallengeKind is set on "challenge" rows ("passcode" | "otp").
	ChallengeKind string
	// LifecycleEvent is the audit event_type on "lifecycle" rows,
	// e.g. "shares.recipient_revoked", "shares.claim_expired".
	LifecycleEvent string
	// ActorID is the creator (or empty for system actions) on
	// lifecycle rows.
	ActorID     string
	RemoteIP    string
	UserAgent   string
	CountryCode string
	RiskScore   int
}

// ListRecipientActivity returns a recipient's full delivery lifecycle:
// verification attempts (share_challenges) merged with the restricted
// access rows that carry that recipient_id (share_access_events). The
// combined stream is sorted newest-first. `limit` caps total rows; each
// source is queried with that same limit before the merge, so the cap
// is an upper bound on output size, not on either underlying source.
func (s *Service) ListRecipientActivity(ctx context.Context, userID, shareID, recipientID string, limit int) ([]RecipientActivityEvent, error) {
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return nil, err
	}
	rec, err := s.deps.Recipients.Get(ctx, recipientID)
	if err != nil || rec.ShareID != share.ID {
		return nil, platerr.New(platerr.CategoryNotFound, "recipient_not_found", "recipient not found")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	challenges, err := s.deps.Challenges.ListByRecipient(ctx, recipientID, limit)
	if err != nil {
		return nil, err
	}
	var accesses []domain.AccessEvent
	if s.deps.AccessLog != nil {
		accesses, _ = s.deps.AccessLog.ListByRecipient(ctx, recipientID, limit)
	}
	lifecycle := s.recipientLifecycleEvents(ctx, recipientID, limit)
	out := make([]RecipientActivityEvent, 0, len(challenges)+len(accesses)+len(lifecycle))
	for _, c := range challenges {
		out = append(out, RecipientActivityEvent{
			Kind:          "challenge",
			ID:            c.ID,
			ShareID:       c.ShareID,
			RecipientID:   c.RecipientID,
			OccurredAt:    c.AttemptedAt,
			Succeeded:     c.Succeeded,
			Reason:        c.Reason,
			ChallengeKind: c.Kind,
			RemoteIP:      c.RemoteIP,
			UserAgent:     c.UserAgent,
			CountryCode:   c.CountryCode,
			RiskScore:     c.RiskScore,
		})
	}
	for _, a := range accesses {
		reason := ""
		if !a.Succeeded {
			if a.Metadata != nil {
				if v, ok := a.Metadata["reason"].(string); ok {
					reason = v
				}
			}
		}
		out = append(out, RecipientActivityEvent{
			Kind:        "access",
			ID:          a.ID,
			ShareID:     a.ShareID,
			RecipientID: a.RecipientID,
			OccurredAt:  a.AccessedAt,
			Succeeded:   a.Succeeded,
			Reason:      reason,
			RemoteIP:    a.RemoteIP,
			UserAgent:   a.UserAgent,
			CountryCode: a.CountryCode,
			RiskScore:   a.RiskScore,
		})
	}
	for _, ev := range lifecycle {
		out = append(out, RecipientActivityEvent{
			Kind:           "lifecycle",
			ID:             ev.ID,
			ShareID:        share.ID,
			RecipientID:    recipientID,
			OccurredAt:     ev.OccurredAt,
			Succeeded:      lifecycleSucceeded(ev.EventType),
			LifecycleEvent: ev.EventType,
			ActorID:        ev.ActorID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// recipientLifecycleEvents pulls the audit rows describing what was
// done to this recipient (invited, revoked, passcode rotated) AND to
// every claim they held (issued, revoked, expired). The recipient
// view on the UI uses this to show the full lifecycle — challenges
// and downloads alone don't tell the operator that a creator rotated
// a passcode or that the ClaimExpiryJob cleared an old cookie.
//
// Uses two query shapes:
//
//	subject_type=share_recipient, subject_id=rid — recipient-scoped
//	subject_type=share_claim,     subject_id=cid — one per claim the
//	                                               recipient holds
//
// Best-effort: if audit isn't configured, returns empty so the
// timeline still renders challenges + accesses.
func (s *Service) recipientLifecycleEvents(ctx context.Context, recipientID string, limit int) []auditdomain.AuditEvent {
	if s.deps.Audit == nil {
		return nil
	}
	out := []auditdomain.AuditEvent{}
	recEvents, _ := s.deps.Audit.List(ctx, auditapp.AuditQuery{
		SubjectType: auditdomain.SubjectTypeRecipient,
		SubjectID:   recipientID,
		Limit:       limit,
	})
	out = append(out, recEvents...)
	if s.deps.Claims != nil {
		claims, _ := s.deps.Claims.ListByRecipient(ctx, recipientID)
		for _, c := range claims {
			claimEvents, _ := s.deps.Audit.List(ctx, auditapp.AuditQuery{
				SubjectType: auditdomain.SubjectTypeClaim,
				SubjectID:   c.ID,
				Limit:       limit,
			})
			out = append(out, claimEvents...)
		}
	}
	return out
}

// lifecycleSucceeded maps a lifecycle event type to a boolean "did
// something positive happen for this recipient" flag so the UI can
// tint row state consistently with challenge/access rows.
// claim_issued is the one positive event; the rest are applied-state
// transitions (revokes, rotations, expirations) that the operator
// reads as "something was taken away" and we render them as denied.
func lifecycleSucceeded(eventType string) bool {
	switch eventType {
	case auditdomain.EventShareRecipientAdded,
		auditdomain.EventShareRecipientReactivated,
		auditdomain.EventShareAccessRequestApproved,
		auditdomain.EventShareClaimIssued:
		return true
	default:
		return false
	}
}

// deliverOTP routes a freshly minted one-time code to the recipient.
// Returns echo=true only when the code should be surfaced in the response
// (dev mode, no dispatcher). With a dispatcher configured the code is sent
// out-of-band and echo stays false; a dispatch error is propagated so the
// recipient retries rather than the code leaking as a fallback. With
// neither dispatcher nor dev echo it fails closed — this only happens for a
// share created before the deployment's OTP delivery was removed, since
// CreateShare refuses require_otp shares in that configuration.
func (s *Service) deliverOTP(ctx context.Context, share domain.Share, rec domain.Recipient, claim domain.Claim, rawOTP string) (bool, error) {
	if s.deps.OTPDispatcher != nil {
		msg := OTPMessage{
			ShareID:        share.ID,
			RecipientID:    rec.ID,
			RecipientEmail: rec.Email,
			Code:           rawOTP,
		}
		if claim.OTPExpiresAt != nil {
			msg.ExpiresAt = *claim.OTPExpiresAt
		}
		if err := s.deps.OTPDispatcher.DispatchOTP(ctx, msg); err != nil {
			return false, platerr.New(platerr.CategoryInternal, "otp_dispatch_failed", "could not deliver the one-time code; please try again")
		}
		return false, nil
	}
	if s.deps.DevModeOTPEcho {
		return true, nil
	}
	return false, platerr.New(platerr.CategoryInternal, "otp_delivery_unavailable", "one-time-code delivery is not configured on this deployment")
}

// otpChannel labels how OTPs reach recipients for the audit trail.
func (s *Service) otpChannel() string {
	if s.deps.OTPDispatcher != nil {
		return "dispatcher"
	}
	return "dev_echo"
}

func (s *Service) newClaim(ctx context.Context, share domain.Share, rec domain.Recipient, now time.Time, rctx RemoteContext) (domain.Claim, string, string, error) {
	raw := newClaimToken()
	exp := now.Add(s.deps.ClaimTTL)
	if !share.ExpiresAt.IsZero() && exp.After(share.ExpiresAt) {
		exp = share.ExpiresAt
	}
	claim := domain.Claim{
		ID:          s.deps.IDs.New("shr_clm"),
		ShareID:     share.ID,
		RecipientID: rec.ID,
		TokenHash:   domain.HashClaimToken(raw),
		IssuedAt:    now,
		ExpiresAt:   exp,
		RemoteIP:    rctx.RemoteIP,
		UserAgent:   rctx.UserAgent,
	}
	var rawOTP string
	if share.RequireOTP {
		rawOTP = newOTPCode()
		// OTP hash is salted by the claim's own TokenHash so a leaked
		// OTP on one claim row can't be replayed on another.
		claim.OTPPending = true
		claim.OTPHash = domain.HashPasscode(claim.TokenHash, []byte(rawOTP))
		otpExp := now.Add(s.deps.OTPTTL)
		if otpExp.After(exp) {
			otpExp = exp
		}
		claim.OTPExpiresAt = &otpExp
	}
	if err := s.deps.Claims.Put(ctx, claim); err != nil {
		return domain.Claim{}, "", "", platerr.New(platerr.CategoryInternal, "persist_claim", err.Error())
	}
	return claim, raw, rawOTP, nil
}

func (s *Service) recordChallenge(ctx context.Context, shareID, recipientID, kind string, succeeded bool, reason string, rctx RemoteContext, now time.Time, extra map[string]any) {
	c := domain.Challenge{
		ID:          s.deps.IDs.New("shr_chg"),
		ShareID:     shareID,
		RecipientID: recipientID,
		Kind:        kind,
		Succeeded:   succeeded,
		Reason:      reason,
		RemoteIP:    rctx.RemoteIP,
		UserAgent:   rctx.UserAgent,
		AttemptedAt: now,
		RiskScore:   rctx.RiskScore,
		CountryCode: rctx.CountryCode,
		Metadata:    extra,
	}
	_ = s.deps.Challenges.Append(ctx, c)
	if !succeeded {
		s.emitAudit(ctx, auditdomain.EventShareChallengeFailed, auditdomain.SubjectTypeShare, shareID, "", map[string]any{
			"recipient_id": recipientID,
			"kind":         kind,
			"reason":       reason,
			"remote_ip":    rctx.RemoteIP,
			"user_agent":   rctx.UserAgent,
			"risk_score":   rctx.RiskScore,
		})
	}
}

// newPasscode returns a random 8-char base32 string (40 bits of entropy)
// and a 16-byte salt.
func newPasscode() (string, []byte) {
	raw := make([]byte, 5) // 40 bits
	_, _ = rand.Read(raw)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	code := strings.ToUpper(strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="))
	return code, salt
}

// newClaimToken returns a random URL-safe token stored HttpOnly in the
// recipient's browser.
func newClaimToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// newOTPCode returns a 6-digit numeric code. Not as strong as a random
// base32 string, but easier for recipients to type.
func newOTPCode() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n = n % 1000000
	out := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		out[i] = byte('0' + n%10)
		n /= 10
	}
	return string(out)
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
