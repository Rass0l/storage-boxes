package domain

import "time"

// AccessEvent is a single row in share_access_events. Always append-only
// (enforced by trigger in migration 007).
type AccessEvent struct {
	ID      string
	ShareID string
	// RecipientID is set for every restricted-share access (success,
	// denial, and stream-interrupted) so the recipient timeline can
	// render the full delivery lifecycle without reverse-joining
	// share_claims. Empty on public-link shares.
	RecipientID string
	RemoteIP    string
	UserAgent   string
	Referer     string
	Succeeded   bool
	AccessedAt  time.Time
	RiskScore   int
	CountryCode string
	Metadata    map[string]any
}
