package domain

import "time"

// Challenge kinds.
const (
	ChallengePasscode = "passcode"
	ChallengeOTP      = "otp"
)

// Denial reasons — written to share_challenges.reason, share_access_events
// metadata, and audit metadata so operators can slice the activity log by
// why something was blocked.
const (
	ReasonPasscodeMismatch  = "passcode_mismatch"
	ReasonRecipientRevoked  = "recipient_revoked"
	ReasonRecipientUnknown  = "recipient_unknown"
	ReasonDomainNotAllowed  = "domain_not_allowed"
	ReasonOTPRequired       = "otp_required"
	ReasonOTPMismatch       = "otp_mismatch"
	ReasonOTPExpired        = "otp_expired"
	ReasonOTPDispatchFailed = "otp_dispatch_failed"
	ReasonClaimRequired     = "claim_required"
	ReasonClaimMissing      = "claim_missing"
	ReasonClaimExpired      = "claim_expired"
	ReasonClaimRevoked      = "claim_revoked"
	ReasonShareNotAvailable = "share_not_available"
	ReasonShareExhausted    = "share_exhausted"
	ReasonRateLimited       = "rate_limited"
)

// Challenge is an append-only record of a single verification attempt
// (passcode or OTP). Successful attempts get Succeeded=true; failures carry
// a Reason string. Challenges live forever alongside share_access_events so
// the recipient-scoped audit view can interleave them by attempted_at.
type Challenge struct {
	ID          string
	ShareID     string
	RecipientID string // may be empty when the email didn't match any recipient
	Kind        string
	Succeeded   bool
	Reason      string
	RemoteIP    string
	UserAgent   string
	AttemptedAt time.Time
	RiskScore   int
	CountryCode string
	Metadata    map[string]any
}
