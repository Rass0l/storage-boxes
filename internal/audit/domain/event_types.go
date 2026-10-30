package domain

const (
	EventLoginSucceeded = "identity.login_succeeded"
	EventLoginFailed    = "identity.login_failed"
	EventLogout         = "identity.logout"

	EventBoxCreated   = "vault.box_created"
	EventBoxDeleted   = "vault.box_deleted"
	EventBoxUnlocked  = "vault.box_unlocked"
	EventBoxUnlockBad = "vault.box_unlock_failed"
	EventFileUploaded = "vault.file_uploaded"
	EventFileDeleted  = "vault.file_deleted"
	EventFileRead     = "vault.file_read" // emitted after blob open succeeds

	EventShareCreated        = "shares.created"
	EventShareSettingsEdited = "shares.settings_updated"
	EventShareAccessed       = "shares.accessed"
	EventShareAccessDenied   = "shares.access_denied"
	EventShareRevoked        = "shares.revoked"
	EventShareExpired        = "shares.expired"
	EventSharePurged         = "shares.purged"
	// EventSharePurgePartial is a non-terminal marker emitted when a
	// best-effort inline stage-blob delete fails during box-deletion
	// cascade. It is NOT a convergence record — the worker's purge job
	// emits the terminal EventSharePurged only after status actually
	// flips. Declared as a constant so the audit vocabulary stays
	// discoverable and greppable, like every other share event.
	EventSharePurgePartial = "shares.purge_partial"

	// Restricted-share lifecycle — recipients, challenges, claims.
	// Keep the "shares." namespace so existing audit filters still match.
	EventShareRecipientAdded     = "shares.recipient_added"
	EventShareRecipientRevoked   = "shares.recipient_revoked"
	EventSharePasscodeRotated    = "shares.passcode_rotated"
	EventShareChallengeIssued    = "shares.challenge_issued"
	EventShareChallengeSucceeded = "shares.challenge_succeeded"
	EventShareChallengeFailed    = "shares.challenge_failed"
	EventShareClaimIssued        = "shares.claim_issued"
	EventShareClaimRevoked       = "shares.claim_revoked"
	EventShareClaimExpired       = "shares.claim_expired"
	EventShareReconciled         = "shares.reconciled"

	// Owner-approved recipient access requests (migration 017). Still in the
	// "shares." namespace so existing audit filters keep matching. An access
	// request is not verification, not a claim, and not authorization — these
	// events record the request lifecycle and how a decision affected the
	// recipient policy. The downstream verify/claim/delivery events
	// (shares.challenge_*, .claim_*, .accessed, .access_denied) continue to
	// cover what happens after approval, attributed to the recipient the
	// approval created/reactivated.
	EventShareAccessRequested          = "shares.access_requested"
	EventShareAccessRequestDuplicate   = "shares.access_request_duplicate"
	EventShareAccessRequestBlocked     = "shares.access_request_blocked" // meta: phase=submit|approve, reason
	EventShareAccessRequestApproved    = "shares.access_request_approved"
	EventShareAccessRequestDenied      = "shares.access_request_denied"
	EventShareAccessRequestExpired     = "shares.access_request_expired"
	EventShareAccessRequestSuperseded  = "shares.access_request_superseded"
	EventShareAccessRequestsReconciled = "shares.access_requests_reconciled" // worker summary
	// EventShareRecipientReactivated marks a previously-revoked recipient
	// being brought back to life by an access-request approval (with a fresh
	// passcode). Distinct from recipient_added so the recipient timeline
	// doesn't show two "invited" events for one recipient row.
	EventShareRecipientReactivated = "shares.recipient_reactivated"
)

const (
	SubjectTypeUser          = "user"
	SubjectTypeBox           = "box"
	SubjectTypeFile          = "file"
	SubjectTypeShare         = "share"
	SubjectTypeRecipient     = "share_recipient"
	SubjectTypeClaim         = "share_claim"
	SubjectTypeAccessRequest = "share_access_request"
)
