package domain

import "time"

// Share states. A share starts active, may be revoked by the owner, expires
// after ExpiresAt, and is purged once the worker has destroyed its staged
// object and settled audit.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
	StatusExpired = "expired"
	StatusPurged  = "purged"

	// Access modes. AccessModePublic preserves the original temporary-link
	// behavior: anyone with the raw token can download until the share
	// expires or the download cap is hit. AccessModeRestricted requires the
	// caller to be on the recipient list AND to have completed passcode
	// verification (and OTP, when RequireOTP is set) before delivery.
	AccessModePublic     = "public"
	AccessModeRestricted = "restricted"
)

type Share struct {
	ID                       string
	BoxID                    string
	FileEntryID              string
	TokenHash                string
	Status                   string
	AccessMode               string
	RecipientDomainAllowlist []string
	RequireOTP               bool
	ExpiresAt                time.Time
	MaxDownloads             int
	DownloadCount            int
	CreatedBy                string
	CreatedAt                time.Time
	RevokedAt                *time.Time
	PurgeRequestedAt         *time.Time
}

// IsRestricted reports whether a share requires recipient verification.
func (s Share) IsRestricted() bool { return s.AccessMode == AccessModeRestricted }

// IsDeliverable reports whether a share can serve a public download right
// now, ignoring download-count enforcement (that's counted separately).
//
// The purge_requested_at stamp is the authoritative "stop serving" flag:
// any code path that intends to tear a share down (Revoke, ShareExpiryJob,
// SharePurgeJob, Service.PurgeByBox from a box soft-delete) stamps it
// FIRST, before flipping status or touching stage bytes. A share with a
// non-nil PurgeRequestedAt is therefore non-deliverable even if its
// status is still `active` — closing the race between stamp and status
// flip, and between inline stage-blob deletion and the status update
// during a box soft-delete.
func (s Share) IsDeliverable(now time.Time) bool {
	if s.PurgeRequestedAt != nil {
		return false
	}
	if s.Status != StatusActive {
		return false
	}
	if !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now) {
		return false
	}
	return true
}
