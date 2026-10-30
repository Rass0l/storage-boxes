package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"time"
)

// Recipient is an allowed destination for a restricted share. Each recipient
// holds its own passcode (stored as PBKDF2-style salt+hash) which must be
// presented to obtain a claim. Revocation is a stamp, not a delete: we keep
// the row so audit history remains queryable.
type Recipient struct {
	ID                string
	ShareID           string
	Email             string // original-cased, for display
	EmailNormalized   string // lower-cased, used for lookup & domain checks
	PasscodeHash      []byte
	PasscodeSalt      []byte
	PasscodeRotatedAt *time.Time
	VerifiedAt        *time.Time
	RevokedAt         *time.Time
	FailedAttempts    int
	LastAttemptAt     *time.Time
	CreatedAt         time.Time
}

// IsActive reports whether this recipient may currently attempt to verify.
// A revoked recipient is permanently blocked; callers should reject before
// any passcode comparison so we don't leak passcode-match signal.
func (r Recipient) IsActive() bool { return r.RevokedAt == nil }

// NormalizeEmail lower-cases and trims. Restricted share domain allowlists
// compare against EmailNormalized to avoid casing surprises.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// HashPasscode derives a hash of (salt || passcode). Kept deliberately
// simple — the passcodes are ~40-bit random base32 strings so a single
// SHA-256 with per-recipient salt is sufficient for the threat model
// (offline attacker who stole the DB still needs 2^40 trials per
// recipient, and we rate-limit online attempts via FailedAttempts).
func HashPasscode(salt, passcode []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(passcode)
	return h.Sum(nil)
}

// PasscodeMatches is a constant-time compare.
func PasscodeMatches(salt, hash, passcode []byte) bool {
	return subtle.ConstantTimeCompare(HashPasscode(salt, passcode), hash) == 1
}

// DomainAllowed reports whether email's domain satisfies the share's
// allowlist. Empty allowlist = no constraint.
func DomainAllowed(email string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return false
	}
	dom := strings.ToLower(email[at+1:])
	for _, rule := range allowlist {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}
		if rule == dom {
			return true
		}
		// Allow leading "." to match any subdomain, e.g. ".example.com".
		if strings.HasPrefix(rule, ".") && strings.HasSuffix(dom, rule) {
			return true
		}
	}
	return false
}
