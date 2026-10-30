package api

type UpdateShareRequest struct {
	// ExpirySeconds, when > 0, rewrites expires_at to now + seconds.
	ExpirySeconds int64 `json:"expiry_seconds,omitempty"`
	// MaxDownloads, when not nil, updates the cap. JSON `null` or
	// missing key leaves the cap unchanged.
	MaxDownloads *int `json:"max_downloads,omitempty"`
}

type CreateShareRequest struct {
	BoxID         string `json:"box_id"`
	FileEntryID   string `json:"file_entry_id"`
	ExpirySeconds int64  `json:"expiry_seconds"`
	MaxDownloads  int    `json:"max_downloads"`
	// AccessMode is "public" (default — temporary link) or "restricted"
	// (requires per-recipient passcode verification). Unknown values
	// are rejected by the service.
	AccessMode      string   `json:"access_mode,omitempty"`
	DomainAllowlist []string `json:"domain_allowlist,omitempty"`
	RequireOTP      bool     `json:"require_otp,omitempty"`
	RecipientEmails []string `json:"recipient_emails,omitempty"`
}

// RecipientDTO is the safe projection of a domain.Recipient: passcode
// material is deliberately absent.
type RecipientDTO struct {
	ID              string `json:"id"`
	ShareID         string `json:"share_id"`
	Email           string `json:"email"`
	EmailNormalized string `json:"email_normalized"`
	VerifiedAt      string `json:"verified_at,omitempty"`
	RevokedAt       string `json:"revoked_at,omitempty"`
	FailedAttempts  int    `json:"failed_attempts"`
	CreatedAt       string `json:"created_at"`
}

// RecipientInviteDTO carries a freshly-provisioned recipient + its raw
// passcode. Returned exactly once at create/add time.
type RecipientInviteDTO struct {
	RecipientDTO
	Passcode string `json:"passcode"`
}

type AddRecipientsRequest struct {
	Emails []string `json:"emails"`
}

type AddRecipientsResponse struct {
	Items []RecipientInviteDTO `json:"items"`
}

type RotatePasscodeResponse struct {
	RecipientDTO
	Passcode string `json:"passcode"`
}

type RecipientListResponse struct {
	Items []RecipientDTO `json:"items"`
}

type ChallengeDTO struct {
	ID          string `json:"id"`
	ShareID     string `json:"share_id"`
	RecipientID string `json:"recipient_id,omitempty"`
	Kind        string `json:"kind"`
	Succeeded   bool   `json:"succeeded"`
	Reason      string `json:"reason,omitempty"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	AttemptedAt string `json:"attempted_at"`
	RiskScore   int    `json:"risk_score"`
	CountryCode string `json:"country_code,omitempty"`
}

type ChallengeListResponse struct {
	Items []ChallengeDTO `json:"items"`
}

// RecipientActivityDTO is a unified row covering verification attempts
// (`share_challenges`), restricted-delivery rows (`share_access_events`),
// and the recipient/claim lifecycle audit stream
// (`shares.recipient_added|_revoked|_passcode_rotated`,
//
//	`shares.claim_issued|_revoked|_expired`).
//
// `kind` is the discriminator; per-kind optional fields are populated as
// described below.
type RecipientActivityDTO struct {
	// Kind: "challenge" | "access" | "lifecycle".
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	ShareID     string `json:"share_id"`
	RecipientID string `json:"recipient_id"`
	OccurredAt  string `json:"occurred_at"`
	// Succeeded: for challenges/accesses, the persisted outcome. For
	// lifecycle rows, true iff the event is a positive transition
	// (recipient_added, claim_issued); false for revokes / rotations
	// / expirations so the UI can tint them consistently.
	Succeeded bool   `json:"succeeded"`
	Reason    string `json:"reason,omitempty"`
	// ChallengeKind: set on "challenge" rows ("passcode" | "otp").
	ChallengeKind string `json:"challenge_kind,omitempty"`
	// LifecycleEvent: audit event type on "lifecycle" rows.
	LifecycleEvent string `json:"lifecycle_event,omitempty"`
	// ActorID: creator user ID on lifecycle rows, empty for system
	// actions (e.g. ClaimExpiryJob).
	ActorID     string `json:"actor_id,omitempty"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	RiskScore   int    `json:"risk_score"`
}

type RecipientActivityListResponse struct {
	Items []RecipientActivityDTO `json:"items"`
}

type ClaimDTO struct {
	ID          string `json:"id"`
	ShareID     string `json:"share_id"`
	RecipientID string `json:"recipient_id"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	OTPPending  bool   `json:"otp_pending"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
}

type ClaimListResponse struct {
	Items []ClaimDTO `json:"items"`
}

type CreateShareResponse struct {
	ID               string   `json:"id"`
	Token            string   `json:"token"`
	URL              string   `json:"url"`
	BoxID            string   `json:"box_id"`
	FileEntryID      string   `json:"file_entry_id"`
	Status           string   `json:"status"`
	ExpiresAt        string   `json:"expires_at"`
	MaxDownloads     int      `json:"max_downloads"`
	DownloadCount    int      `json:"download_count"`
	CreatedAt        string   `json:"created_at"`
	PurgeRequestedAt string   `json:"purge_requested_at,omitempty"`
	Deliverable      bool     `json:"deliverable"`
	AccessMode       string   `json:"access_mode"`
	RequireOTP       bool     `json:"require_otp,omitempty"`
	DomainAllowlist  []string `json:"domain_allowlist,omitempty"`
	// Recipients is populated exactly once at create time for restricted
	// shares — the creator must transmit passcodes out-of-band. Absent
	// on public shares.
	Recipients []RecipientInviteDTO `json:"recipients,omitempty"`
}

type ShareResponse struct {
	ID            string `json:"id"`
	BoxID         string `json:"box_id"`
	FileEntryID   string `json:"file_entry_id"`
	Status        string `json:"status"`
	ExpiresAt     string `json:"expires_at"`
	MaxDownloads  int    `json:"max_downloads"`
	DownloadCount int    `json:"download_count"`
	CreatedAt     string `json:"created_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
	// PurgeRequestedAt is set as soon as any tear-down path stamps it
	// — Revoke, TTL expiry, download-count exhaustion, or a box
	// soft-delete (which cascades through Service.PurgeByBox). Present
	// even while `status` is still `active`, so the UI can disambiguate
	// "active and serving" from "active but pending purge, not
	// serving". Mirrors the field on domain.Share.
	PurgeRequestedAt string `json:"purge_requested_at,omitempty"`
	// Deliverable is the computed Share.IsDeliverable(now) value at
	// the moment the response was built. Saves the UI from
	// re-implementing the compound check (status active, not expired,
	// no purge stamp). Cap exhaustion is NOT folded in here — the
	// caller sees it via DownloadCount vs MaxDownloads.
	Deliverable     bool     `json:"deliverable"`
	AccessMode      string   `json:"access_mode"`
	RequireOTP      bool     `json:"require_otp,omitempty"`
	DomainAllowlist []string `json:"domain_allowlist,omitempty"`
}

type ShareListResponse struct {
	Items []ShareResponse `json:"items"`
}

type AccessEventResponse struct {
	ID string `json:"id"`
	// RecipientID is populated on restricted-share rows. Empty for
	// public-share accesses. The SharesPage access-log renderer reads
	// it to distinguish temporary-link hits from recipient-attributed
	// deliveries without hitting the recipient endpoint per row.
	RecipientID string `json:"recipient_id,omitempty"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Succeeded   bool   `json:"succeeded"`
	AccessedAt  string `json:"accessed_at"`
	RiskScore   int    `json:"risk_score"`
	CountryCode string `json:"country_code,omitempty"`
}

type AccessEventListResponse struct {
	Items []AccessEventResponse `json:"items"`
}

// AccessRequestDTO is the OWNER-facing projection of a
// domain.AccessRequest. It exposes the full row (status, decision metadata,
// requester contact + enrichment) because the owner is authenticated and
// owns the share. This is NOT returned on any public endpoint.
type AccessRequestDTO struct {
	ID              string `json:"id"`
	ShareID         string `json:"share_id"`
	RequesterEmail  string `json:"requester_email"`
	RequesterDomain string `json:"requester_domain"`
	Message         string `json:"message,omitempty"`
	Status          string `json:"status"`
	RecipientID     string `json:"recipient_id,omitempty"`
	DecidedBy       string `json:"decided_by,omitempty"`
	DecidedAt       string `json:"decided_at,omitempty"`
	DecisionReason  string `json:"decision_reason,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	RemoteIP        string `json:"remote_ip,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	CountryCode     string `json:"country_code,omitempty"`
	RiskScore       int    `json:"risk_score"`
	CreatedAt       string `json:"created_at"`
	// RecipientState is the CURRENT state of the recipient an approval linked
	// ("active" | "revoked" | "missing"), or empty when the request has no
	// recipient. `status` is the historical decision (kept for compliance);
	// this is current truth, so an approved request whose recipient was later
	// revoked reads as `status=approved` + `recipient_state=revoked` rather
	// than implying live access.
	RecipientState string `json:"recipient_state,omitempty"`
}

type AccessRequestListResponse struct {
	Items []AccessRequestDTO `json:"items"`
}

// DenyAccessRequestRequest is the optional body for a deny: an owner may
// attach a reason that lands in the audit trail and the request row.
type DenyAccessRequestRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AccessRequestApproveResponse is returned once on approval. Passcode is the
// freshly-minted recipient passcode (present only when a passcode was minted —
// a brand-new or reactivated recipient) for the owner to transmit out-of-band;
// it is never stored or returned again. Reactivated reports whether a
// previously-revoked recipient was brought back to life.
type AccessRequestApproveResponse struct {
	Request     AccessRequestDTO `json:"request"`
	Recipient   RecipientDTO     `json:"recipient"`
	Passcode    string           `json:"passcode,omitempty"`
	Reactivated bool             `json:"reactivated"`
}

// PublicAccessRequestResponse is the ONLY shape returned to unauthenticated
// callers from the gateway's request-access / request-status endpoints. It
// carries a coarse status and nothing else — no ids, owner data, decision
// metadata, secrets, or file metadata.
type PublicAccessRequestResponse struct {
	Status string `json:"status"`
}
