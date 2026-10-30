package app

import (
	"context"
	"errors"
	"time"

	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ErrAccessRequestNotPending is the sentinel an AccessRequestRepository.Decide
// returns when the targeted row is no longer pending (a lost race or an
// already-decided row). The worker treats it as a harmless no-op; the owner
// approve/deny handlers map it to a conflict.
var ErrAccessRequestNotPending = errors.New("access request not pending")

// Coarse public statuses returned by the gateway-facing endpoints. These are
// the ONLY values exposed to unauthenticated callers — never decision
// metadata, recipient ids, owner identity, secrets, or file metadata. Internal
// lifecycle states (expired/superseded) collapse to "none" so the public
// surface doesn't leak worker bookkeeping.
const (
	PublicStatusNone            = "none"
	PublicStatusPending         = "pending"
	PublicStatusApproved        = "approved"
	PublicStatusDenied          = "denied"
	PublicStatusRecipientActive = "recipient_active" // already a recipient — just verify
)

// SubmitAccessRequestResult is what the gateway returns to a visitor after a
// submission. It carries only a coarse status.
type SubmitAccessRequestResult struct {
	Status string
}

// AccessRequestStatusResult is the coarse status for a (token, email) pair.
type AccessRequestStatusResult struct {
	Status string
}

// ApproveAccessRequestResult bundles the recipient the approval
// added/reactivated and, when a fresh passcode was minted, the raw passcode —
// returned exactly once for the owner to transmit out-of-band. Reactivated is
// true when an existing revoked recipient was brought back to life.
type ApproveAccessRequestResult struct {
	Request     domain.AccessRequest
	Recipient   domain.Recipient
	Passcode    string
	Reactivated bool
}

// ApprovalMode selects the recipient write an atomic approval performs.
type ApprovalMode string

const (
	ApprovalModeNew        ApprovalMode = "new"        // INSERT a fresh recipient
	ApprovalModeReactivate ApprovalMode = "reactivate" // un-revoke + rotate the passcode
	ApprovalModeLink       ApprovalMode = "link"       // recipient already active; only link
)

// ApprovalPlan is the fully-resolved approval the service hands to the repo's
// ApproveAtomic. The service owns the policy decisions (passcode minting, ID
// generation, mode selection); the repo executes the whole plan as one
// transaction. Recipient carries the row to INSERT (New) or the existing row
// (Reactivate/Link); for Reactivate its PasscodeHash/PasscodeSalt are the
// freshly-minted values to write.
type ApprovalPlan struct {
	RequestID string
	DecidedBy string
	Reason    string
	Now       time.Time
	Mode      ApprovalMode
	Recipient domain.Recipient
}

// SubmitAccessRequest is the public, unauthenticated entry point from the
// gateway. A visitor who isn't an allowed recipient asks the owner for access.
// It creates a PENDING request only; it grants nothing. The requester must
// still be approved AND complete the normal verification flow before delivery.
//
// Information leakage is deliberately bounded: it returns only a coarse status
// and never private file metadata, internal ids, or owner data. It never
// dereferences deps.Files (the gateway wires it nil) — fulfillability is
// re-checked at approval time on the API, which does have Files.
func (s *Service) SubmitAccessRequest(ctx context.Context, rawToken, email, message string, rctx RemoteContext) (SubmitAccessRequestResult, error) {
	if s.deps.AccessRequests == nil {
		return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryInternal, "access_requests_not_configured", "access requests are not configured on this deployment")
	}
	share, err := s.ResolveByToken(ctx, rawToken)
	if err != nil {
		return SubmitAccessRequestResult{}, err
	}
	if !share.IsRestricted() {
		// Public links don't gate delivery, so there's nothing to request.
		return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "share_not_restricted", "this share does not require access requests")
	}
	now := s.deps.Clock.Now().UTC()
	if !share.IsDeliverable(now) {
		s.emitAccessRequestBlocked(ctx, share.ID, "submit", domain.AccessReasonShareUnavailable, "", "", rctx)
		return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryNotFound, "share_not_available", "share is not available")
	}
	// Rate-limit submissions per (share, IP) so one source can't spam
	// pending rows across many distinct emails.
	if s.deps.AccessRequestRateLimit > 0 && rctx.RemoteIP != "" {
		recent, _ := s.deps.AccessRequests.CountRecentByShareIP(ctx, share.ID, rctx.RemoteIP, now.Add(-s.deps.AccessRequestRateWindow))
		if recent >= s.deps.AccessRequestRateLimit {
			s.emitAccessRequestBlocked(ctx, share.ID, "submit", domain.AccessReasonRateLimited, "", "", rctx)
			return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryAuthz, "rate_limited", "too many requests")
		}
	}
	normalized := domain.NormalizeEmail(email)
	if !validRecipientEmail(normalized) {
		return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryValidation, "invalid_requester_email", "a valid email address is required")
	}
	if !domain.DomainAllowed(normalized, share.RecipientDomainAllowlist) {
		// A request from a disallowed domain can never be approved, so we
		// reject it up front (with an audit record) rather than parking an
		// un-approvable pending row.
		s.emitAccessRequestBlocked(ctx, share.ID, "submit", domain.AccessReasonDomainNotAllowed, normalized, "", rctx)
		return SubmitAccessRequestResult{}, platerr.New(platerr.CategoryAuthz, "domain_not_allowed", "your email domain is not permitted for this share")
	}
	// Already an active recipient? They don't need to request — point them at
	// verification. (A token holder supplied this email, so revealing
	// recipient status to them is bounded by their possession of the token.)
	if s.deps.Recipients != nil {
		if rec, rerr := s.deps.Recipients.GetByShareEmail(ctx, share.ID, normalized); rerr == nil && rec.ID != "" && rec.RevokedAt == nil {
			s.emitAccessRequestDuplicate(ctx, share.ID, "", normalized, domain.AccessReasonRecipientActive, rctx)
			return SubmitAccessRequestResult{Status: PublicStatusRecipientActive}, nil
		}
	}
	// Dedupe: an open pending request short-circuits to its current status.
	if existing, derr := s.deps.AccessRequests.GetPendingByShareEmail(ctx, share.ID, normalized); derr == nil && existing.ID != "" {
		s.emitAccessRequestDuplicate(ctx, share.ID, existing.ID, normalized, "pending", rctx)
		return SubmitAccessRequestResult{Status: PublicStatusPending}, nil
	}
	exp := now.Add(s.deps.AccessRequestTTL)
	ar := domain.AccessRequest{
		ID:                       s.deps.IDs.New("shr_areq"),
		ShareID:                  share.ID,
		RequesterEmail:           normalized,
		RequesterEmailNormalized: normalized,
		RequesterDomain:          emailDomain(normalized),
		Message:                  clampMessage(message),
		Status:                   domain.AccessRequestPending,
		ExpiresAt:                &exp,
		RemoteIP:                 rctx.RemoteIP,
		UserAgent:                rctx.UserAgent,
		Referer:                  rctx.Referer,
		RiskScore:                rctx.RiskScore,
		CountryCode:              rctx.CountryCode,
		CreatedAt:                now,
	}
	if err := s.deps.AccessRequests.Put(ctx, ar); err != nil {
		// A partial-unique-index conflict means a concurrent submit won the
		// race; treat it as a duplicate rather than a 500.
		s.emitAccessRequestDuplicate(ctx, share.ID, "", normalized, "pending", rctx)
		return SubmitAccessRequestResult{Status: PublicStatusPending}, nil
	}
	s.emitAudit(ctx, auditdomain.EventShareAccessRequested, auditdomain.SubjectTypeAccessRequest, ar.ID, "", map[string]any{
		"share_id":        share.ID,
		"requester_email": normalized,
		"domain":          ar.RequesterDomain,
		"message_present": ar.Message != "",
		"remote_ip":       rctx.RemoteIP,
		"user_agent":      rctx.UserAgent,
		"country_code":    rctx.CountryCode,
		"risk_score":      rctx.RiskScore,
	})
	return SubmitAccessRequestResult{Status: PublicStatusPending}, nil
}

// AccessRequestStatus returns the coarse status for the email a requester
// supplies. Active recipients map to "approved" (verify now); pending maps to
// "pending"; a denied latest maps to "denied"; everything else (expired /
// superseded / never requested) maps to "none". No decision metadata, ids, or
// recipient details are exposed.
func (s *Service) AccessRequestStatus(ctx context.Context, rawToken, email string) (AccessRequestStatusResult, error) {
	if s.deps.AccessRequests == nil {
		return AccessRequestStatusResult{}, platerr.New(platerr.CategoryInternal, "access_requests_not_configured", "access requests are not configured on this deployment")
	}
	share, err := s.ResolveByToken(ctx, rawToken)
	if err != nil {
		return AccessRequestStatusResult{}, err
	}
	if !share.IsRestricted() {
		return AccessRequestStatusResult{Status: PublicStatusNone}, nil
	}
	normalized := domain.NormalizeEmail(email)
	if !validRecipientEmail(normalized) {
		return AccessRequestStatusResult{}, platerr.New(platerr.CategoryValidation, "invalid_requester_email", "a valid email address is required")
	}
	// "approved" reflects CURRENT access truth, not the historical request
	// status: a requester has access only while they are an ACTIVE recipient.
	// We derive `approved` solely from the live recipient row — so if the
	// recipient is later revoked (or never materialized, e.g. after a restore
	// of an approved row whose recipient is gone), the public status stops
	// saying `approved` and the requester is not misled into thinking they can
	// still get in.
	if s.deps.Recipients != nil {
		if rec, rerr := s.deps.Recipients.GetByShareEmail(ctx, share.ID, normalized); rerr == nil && rec.ID != "" && rec.RevokedAt == nil {
			return AccessRequestStatusResult{Status: PublicStatusApproved}, nil
		}
	}
	latest, lerr := s.deps.AccessRequests.GetLatestByShareEmail(ctx, share.ID, normalized)
	if lerr != nil {
		return AccessRequestStatusResult{Status: PublicStatusNone}, nil
	}
	switch latest.Status {
	case domain.AccessRequestPending:
		return AccessRequestStatusResult{Status: PublicStatusPending}, nil
	case domain.AccessRequestDenied:
		return AccessRequestStatusResult{Status: PublicStatusDenied}, nil
	default:
		// `approved` here means the request was approved historically but the
		// recipient is no longer active (revoked / missing) — access is gone,
		// so we report `none`. `expired` / `superseded` likewise map to none.
		// The requester can submit a fresh request if they still need access.
		return AccessRequestStatusResult{Status: PublicStatusNone}, nil
	}
}

// ListAccessRequests returns the access requests for a share (creator-only via
// the Get ownership check). statusFilter "" returns every status.
func (s *Service) ListAccessRequests(ctx context.Context, userID, shareID, statusFilter string, limit int) ([]domain.AccessRequest, error) {
	if s.deps.AccessRequests == nil {
		return nil, platerr.New(platerr.CategoryInternal, "access_requests_not_configured", "access requests are not configured on this deployment")
	}
	if _, err := s.Get(ctx, userID, shareID); err != nil {
		return nil, err
	}
	if statusFilter != "" && !validAccessRequestStatus(statusFilter) {
		return nil, platerr.New(platerr.CategoryValidation, "invalid_status", "unknown access request status filter")
	}
	return s.deps.AccessRequests.ListByShare(ctx, shareID, statusFilter, limit)
}

// ApproveAccessRequest brings the requester into the share's restricted policy
// as a recipient (new or reactivated) and marks the request approved. It is
// NOT authorization: no claim is issued, so the requester must still verify
// with the minted passcode before any download. Every fulfillability gate is
// re-checked at decision time (the share may have expired / been revoked /
// purged, or the file may have been deleted since the request was filed);
// failures leave the request pending and emit an audit record.
func (s *Service) ApproveAccessRequest(ctx context.Context, userID, shareID, requestID string) (ApproveAccessRequestResult, error) {
	if s.deps.AccessRequests == nil {
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryInternal, "access_requests_not_configured", "access requests are not configured on this deployment")
	}
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return ApproveAccessRequestResult{}, err
	}
	ar, err := s.deps.AccessRequests.Get(ctx, requestID)
	if err != nil || ar.ShareID != share.ID {
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryNotFound, "access_request_not_found", "access request not found")
	}
	if !ar.IsPending() {
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "access_request_not_pending", "access request is not pending")
	}
	now := s.deps.Clock.Now().UTC()

	// An OLD request must not be approved as if fresh. A request past its TTL
	// is stale — the requester's window has lapsed — so converge it to expired
	// (exactly what the worker's cleanup would do) regardless of worker timing
	// or whether the worker is even running, and refuse the approval. This
	// also closes the gap where a request the list still shows as `pending`
	// (because the sweep hasn't fired yet) could be silently approved.
	if ar.ExpiresAt != nil && !ar.ExpiresAt.After(now) {
		// decidedBy stays empty: a TTL expiry is a system transition, not an
		// owner decision. The audit event below carries the owner actor +
		// via=approve so the trail shows the owner's attempt surfaced it.
		if derr := s.deps.AccessRequests.Decide(ctx, ar.ID, domain.AccessRequestExpired, "", "", domain.AccessReasonExpiredTTL, now); derr == nil {
			meta := decisionAuditMeta(ar)
			meta["reason"] = domain.AccessReasonExpiredTTL
			meta["via"] = "approve"
			s.emitAudit(ctx, auditdomain.EventShareAccessRequestExpired, auditdomain.SubjectTypeAccessRequest, ar.ID, userID, meta)
		}
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "access_request_expired", "access request has expired")
	}

	// Re-validate fulfillability at decision time. Approve-phase blocks carry
	// the owner actor so the audit explains who attempted the approval.
	if !share.IsRestricted() {
		s.emitAccessRequestBlocked(ctx, share.ID, "approve", domain.AccessReasonShareNotRestricted, ar.RequesterEmailNormalized, userID, RemoteContext{})
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "share_not_restricted", "share is not restricted")
	}
	if share.Status != domain.StatusActive || share.PurgeRequestedAt != nil || !share.IsDeliverable(now) {
		s.emitAccessRequestBlocked(ctx, share.ID, "approve", domain.AccessReasonShareUnavailable, ar.RequesterEmailNormalized, userID, RemoteContext{})
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "share_not_available", "share is not available")
	}
	if !domain.DomainAllowed(ar.RequesterEmailNormalized, share.RecipientDomainAllowlist) {
		s.emitAccessRequestBlocked(ctx, share.ID, "approve", domain.AccessReasonDomainNotAllowed, ar.RequesterEmailNormalized, userID, RemoteContext{})
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryValidation, "domain_not_allowed", "requester domain is not in the allowlist")
	}
	if s.deps.Files != nil {
		if _, ferr := s.deps.Files.LookupFile(ctx, share.BoxID, share.FileEntryID); ferr != nil {
			s.emitAccessRequestBlocked(ctx, share.ID, "approve", domain.AccessReasonFileNotFound, ar.RequesterEmailNormalized, userID, RemoteContext{})
			return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "file_not_found", "the shared file no longer exists")
		}
	}
	if s.deps.Objects != nil {
		if _, oerr := s.deps.Objects.GetObject(ctx, share.ID); oerr != nil {
			s.emitAccessRequestBlocked(ctx, share.ID, "approve", domain.AccessReasonObjectMissing, ar.RequesterEmailNormalized, userID, RemoteContext{})
			return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "object_missing", "the staged share object is missing")
		}
	}

	// Resolve the approval into a single plan: pick the recipient mode and
	// mint a passcode where one is needed. This is pure decision-making — no
	// persistence yet — so a concurrent decision can still pre-empt us at the
	// atomic step below.
	res := ApproveAccessRequestResult{}
	plan := ApprovalPlan{RequestID: ar.ID, DecidedBy: userID, Reason: domain.AccessReasonOwnerApproved, Now: now}
	existing, lookupErr := s.deps.Recipients.GetByShareEmail(ctx, share.ID, ar.RequesterEmailNormalized)
	switch {
	case lookupErr == nil && existing.ID != "" && existing.RevokedAt != nil:
		// Previously revoked → reactivate with a fresh passcode.
		raw, salt := newPasscode()
		rec := existing
		rec.PasscodeSalt = salt
		rec.PasscodeHash = domain.HashPasscode(salt, []byte(raw))
		rec.PasscodeRotatedAt = &now
		rec.RevokedAt = nil
		rec.FailedAttempts = 0
		plan.Mode = ApprovalModeReactivate
		plan.Recipient = rec
		res.Recipient = rec
		res.Passcode = raw
		res.Reactivated = true
	case lookupErr == nil && existing.ID != "":
		// Already an active recipient (owner added them out-of-band after the
		// request arrived). Link the request; mint no new passcode.
		plan.Mode = ApprovalModeLink
		plan.Recipient = existing
		res.Recipient = existing
	default:
		// Brand-new recipient.
		raw, salt := newPasscode()
		rec := domain.Recipient{
			ID:              s.deps.IDs.New("shr_rcp"),
			ShareID:         share.ID,
			Email:           ar.RequesterEmailNormalized,
			EmailNormalized: ar.RequesterEmailNormalized,
			PasscodeSalt:    salt,
			PasscodeHash:    domain.HashPasscode(salt, []byte(raw)),
			CreatedAt:       now,
		}
		plan.Mode = ApprovalModeNew
		plan.Recipient = rec
		res.Recipient = rec
		res.Passcode = raw
	}

	// ONE reliable operation. ApproveAtomic claims the request AND writes the
	// recipient in a single transaction: either the request is approved and
	// the recipient exists+active+linked, or nothing is persisted. A lost
	// race (deny / expire / supersede / another approve won first) returns
	// not-pending and writes nothing; any other failure also rolls back,
	// leaving the request pending and the approval retryable. The request and
	// recipient state can never end up half-applied.
	if err := s.deps.AccessRequests.ApproveAtomic(ctx, plan); err != nil {
		if errors.Is(err, ErrAccessRequestNotPending) {
			return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryConflict, "access_request_not_pending", "access request is not pending")
		}
		return ApproveAccessRequestResult{}, platerr.New(platerr.CategoryInternal, "persist_approve", err.Error())
	}

	// Audit only after the commit — a rolled-back approval leaves no trace.
	switch plan.Mode {
	case ApprovalModeReactivate:
		s.emitAudit(ctx, auditdomain.EventShareRecipientReactivated, auditdomain.SubjectTypeRecipient, res.Recipient.ID, userID, map[string]any{
			"share_id": share.ID, "email": res.Recipient.Email, "via": "access_request", "request_id": ar.ID,
		})
	case ApprovalModeNew:
		s.emitAudit(ctx, auditdomain.EventShareRecipientAdded, auditdomain.SubjectTypeRecipient, res.Recipient.ID, userID, map[string]any{
			"share_id": share.ID, "email": res.Recipient.Email, "via": "access_request", "request_id": ar.ID,
		})
	}
	ar.Status = domain.AccessRequestApproved
	ar.RecipientID = res.Recipient.ID
	ar.DecidedBy = userID
	ar.DecidedAt = &now
	ar.DecisionReason = domain.AccessReasonOwnerApproved
	res.Request = ar
	// The decision event must stand alone as the explanation of what happened:
	// who requested (email/domain/origin), how old the request was, who
	// approved (actor), and HOW the decision changed recipient policy
	// (recipient_mode: new recipient created / revoked one reactivated /
	// already-active one linked, plus the recipient_id).
	meta := decisionAuditMeta(ar)
	meta["recipient_id"] = res.Recipient.ID
	meta["recipient_mode"] = string(plan.Mode)
	meta["reactivated"] = res.Reactivated
	s.emitAudit(ctx, auditdomain.EventShareAccessRequestApproved, auditdomain.SubjectTypeAccessRequest, ar.ID, userID, meta)
	return res, nil
}

// DenyAccessRequest marks a pending request denied. The requester is never made
// a recipient, so delivery stays blocked.
func (s *Service) DenyAccessRequest(ctx context.Context, userID, shareID, requestID, reason string) error {
	if s.deps.AccessRequests == nil {
		return platerr.New(platerr.CategoryInternal, "access_requests_not_configured", "access requests are not configured on this deployment")
	}
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return err
	}
	ar, err := s.deps.AccessRequests.Get(ctx, requestID)
	if err != nil || ar.ShareID != share.ID {
		return platerr.New(platerr.CategoryNotFound, "access_request_not_found", "access request not found")
	}
	if !ar.IsPending() {
		return platerr.New(platerr.CategoryConflict, "access_request_not_pending", "access request is not pending")
	}
	if reason == "" {
		reason = domain.AccessReasonOwnerDenied
	}
	now := s.deps.Clock.Now().UTC()
	if derr := s.deps.AccessRequests.Decide(ctx, ar.ID, domain.AccessRequestDenied, "", userID, reason, now); derr != nil {
		if errors.Is(derr, ErrAccessRequestNotPending) {
			return platerr.New(platerr.CategoryConflict, "access_request_not_pending", "access request is not pending")
		}
		return platerr.New(platerr.CategoryInternal, "persist_decide", derr.Error())
	}
	meta := decisionAuditMeta(ar)
	meta["reason"] = reason
	s.emitAudit(ctx, auditdomain.EventShareAccessRequestDenied, auditdomain.SubjectTypeAccessRequest, ar.ID, userID, meta)
	return nil
}

// decisionAuditMeta builds the self-explanatory core of a decision/expiry audit
// event: who requested (email/domain), from where (remote_ip/country), and how
// OLD the request was (requested_at). Reading the single decision event then
// answers who/where/when-requested without a join back to the request row —
// important when the audit trail is the only record explaining a decision.
func decisionAuditMeta(ar domain.AccessRequest) map[string]any {
	m := map[string]any{
		"share_id":         ar.ShareID,
		"requester_email":  ar.RequesterEmail,
		"requester_domain": ar.RequesterDomain,
		"requested_at":     ar.CreatedAt.Format(time.RFC3339),
	}
	if ar.RemoteIP != "" {
		m["requester_remote_ip"] = ar.RemoteIP
	}
	if ar.CountryCode != "" {
		m["requester_country"] = ar.CountryCode
	}
	return m
}

// emitAccessRequestBlocked records a submit- or approve-phase block (share
// unavailable, domain conflict, missing file/object, rate limited) so the
// audit trail carries every turned-away attempt with a precise reason.
// actorID is the owner on approve-phase blocks (so the trail shows who
// attempted the approval) and empty on public submit-phase blocks.
func (s *Service) emitAccessRequestBlocked(ctx context.Context, shareID, phase, reason, email, actorID string, rctx RemoteContext) {
	meta := map[string]any{
		"share_id": shareID,
		"phase":    phase,
		"reason":   reason,
	}
	if email != "" {
		meta["requester_email"] = email
	}
	if rctx.RemoteIP != "" {
		meta["remote_ip"] = rctx.RemoteIP
	}
	if rctx.UserAgent != "" {
		meta["user_agent"] = rctx.UserAgent
	}
	s.emitAudit(ctx, auditdomain.EventShareAccessRequestBlocked, auditdomain.SubjectTypeShare, shareID, actorID, meta)
}

func (s *Service) emitAccessRequestDuplicate(ctx context.Context, shareID, requestID, email, reason string, rctx RemoteContext) {
	subjectID := requestID
	if subjectID == "" {
		subjectID = shareID
	}
	s.emitAudit(ctx, auditdomain.EventShareAccessRequestDuplicate, auditdomain.SubjectTypeAccessRequest, subjectID, "", map[string]any{
		"share_id":        shareID,
		"requester_email": email,
		"reason":          reason,
		"remote_ip":       rctx.RemoteIP,
		"user_agent":      rctx.UserAgent,
	})
}

func validAccessRequestStatus(s string) bool {
	switch s {
	case domain.AccessRequestPending, domain.AccessRequestApproved, domain.AccessRequestDenied,
		domain.AccessRequestExpired, domain.AccessRequestSuperseded:
		return true
	default:
		return false
	}
}

// emailDomain returns the lower-cased domain part of an already-normalized
// email, or "" when malformed (callers validate first).
func emailDomain(normalized string) string {
	at := lastIndexByte(normalized, '@')
	if at < 0 || at == len(normalized)-1 {
		return ""
	}
	return normalized[at+1:]
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// clampMessage bounds the requester-supplied free-text so a hostile submitter
// can't store an unbounded blob. Kept generous enough for a real note.
func clampMessage(msg string) string {
	const max = 2000
	if len(msg) > max {
		return msg[:max]
	}
	return msg
}
