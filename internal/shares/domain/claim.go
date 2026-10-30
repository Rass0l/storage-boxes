package domain

import (
	"crypto/sha256"
	"time"
)

// Claim is a short-lived, per-recipient session that allows a verified
// recipient to download without re-entering their passcode. The raw claim
// token lives in an HttpOnly cookie scoped to /s/<token>; the server stores
// only its SHA-256 hash (TokenHash).
//
// When RequireOTP is set on the share, a successful passcode verification
// creates a claim with OTPPending=true and an OTPHash/OTPExpiresAt set.
// Delivery is blocked until the recipient completes the OTP step, which
// clears OTPPending. This two-phase layout keeps the cookie in place across
// the passcode → OTP transition so the recipient's attempts all roll up to
// the same claim row in the audit view.
type Claim struct {
	ID           string
	ShareID      string
	RecipientID  string
	TokenHash    []byte
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	OTPPending   bool
	OTPHash      []byte
	OTPExpiresAt *time.Time
	RemoteIP     string
	UserAgent    string
}

// IsActive reports whether the claim can currently be redeemed for a
// download. OTPPending claims are NOT active — they gate the OTP step but
// do not authorize a download yet.
func (c Claim) IsActive(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if !c.ExpiresAt.IsZero() && !c.ExpiresAt.After(now) {
		return false
	}
	if c.OTPPending {
		return false
	}
	return true
}

// HashClaimToken produces the SHA-256 used for DB lookups of the cookie.
func HashClaimToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
