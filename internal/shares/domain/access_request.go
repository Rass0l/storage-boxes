package domain

import "time"

// AccessRequest is a visitor's request for access to a restricted share they
// are not (yet) a recipient of. It is MUTABLE (status transitions + decision
// metadata), mirroring Recipient — the append-only audit ledger preserves the
// decision history; this row carries current state.
//
// Critically, an access request is NOT verification, NOT a claim, and NOT
// authorization by itself. Approval adds/reactivates the requester as a normal
// recipient under the share's existing restricted policy; the requester must
// still complete the normal passcode -> claim -> (optional OTP) -> delivery
// flow before any bytes are served. Restricted shares never become bearer
// links.
type AccessRequest struct {
	ID                       string
	ShareID                  string
	RequesterEmail           string // original-cased, for owner display
	RequesterEmailNormalized string // lower-cased, used for lookup & dedupe
	RequesterDomain          string // domain part, for domain-rule checks/audit
	Message                  string // optional free-text from the requester
	Status                   string
	// RecipientID is set on approval to the recipient row that was created
	// or reactivated, so the request -> recipient -> challenges/accesses
	// chain stays queryable. Empty until approved.
	RecipientID    string
	DecidedBy      string // owner user id on approve/deny; empty for system (worker) transitions
	DecidedAt      *time.Time
	DecisionReason string
	ExpiresAt      *time.Time // pending requests expire after this; nil = no TTL
	RemoteIP       string
	UserAgent      string
	Referer        string
	RiskScore      int
	CountryCode    string
	CreatedAt      time.Time
	Metadata       map[string]any
}

// Access request lifecycle states.
const (
	AccessRequestPending    = "pending"
	AccessRequestApproved   = "approved"
	AccessRequestDenied     = "denied"
	AccessRequestExpired    = "expired"
	AccessRequestSuperseded = "superseded"
)

// Decision reasons — written to share_access_requests.decision_reason and
// carried in audit metadata so operators can slice request history by why a
// decision happened. Submit-time block reasons reuse the same vocabulary as
// the verify flow (domain_not_allowed, share_unavailable) for consistency.
const (
	AccessReasonOwnerApproved      = "owner_approved"
	AccessReasonOwnerDenied        = "owner_denied"
	AccessReasonExpiredTTL         = "expired_ttl"
	AccessReasonShareUnavailable   = "share_unavailable"
	AccessReasonDomainNotAllowed   = "domain_not_allowed"
	AccessReasonRecipientActive    = "recipient_active"
	AccessReasonRecipientMissing   = "recipient_missing"
	AccessReasonFileNotFound       = "file_not_found"
	AccessReasonObjectMissing      = "object_missing"
	AccessReasonShareNotRestricted = "share_not_restricted"
	AccessReasonInvalidEmail       = "invalid_email"
	AccessReasonRateLimited        = "rate_limited"
)

// IsPending reports whether the request is still awaiting an owner decision.
func (a AccessRequest) IsPending() bool { return a.Status == AccessRequestPending }

// IsTerminal reports whether the request has reached a final state and will
// not transition again (approved/denied/expired/superseded). Terminal rows are
// kept as history.
func (a AccessRequest) IsTerminal() bool {
	switch a.Status {
	case AccessRequestApproved, AccessRequestDenied, AccessRequestExpired, AccessRequestSuperseded:
		return true
	default:
		return false
	}
}
