package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	auditapp "github.com/Rass0l/storage-boxes/internal/audit/app"
	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ShareService is the authenticated surface that /api/v1/shares exposes.
type ShareService interface {
	CreateShare(ctx context.Context, input CreateShareInput) (CreateShareResult, error)
	UpdateSettings(ctx context.Context, input UpdateSettingsInput) (domain.Share, error)
	ListByCreator(ctx context.Context, userID string) ([]domain.Share, error)
	Get(ctx context.Context, userID, shareID string) (domain.Share, error)
	Revoke(ctx context.Context, userID, shareID string) error
	ResolveByToken(ctx context.Context, rawToken string) (domain.Share, error)
	ListAccess(ctx context.Context, userID, shareID string, limit int) ([]domain.AccessEvent, error)
}

// RestrictedShareService extends ShareService with the recipient/verification
// surface. Deployments that haven't run migration 015 can leave this nil on
// Deps and the API layer returns 503 for restricted-only routes.
type RestrictedShareService interface {
	AddRecipients(ctx context.Context, in AddRecipientsInput) ([]RecipientInvite, error)
	ListRecipients(ctx context.Context, userID, shareID string) ([]domain.Recipient, error)
	RotateRecipientPasscode(ctx context.Context, userID, shareID, recipientID string) (domain.Recipient, string, error)
	RevokeRecipient(ctx context.Context, userID, shareID, recipientID string) error
	ListRecipientActivity(ctx context.Context, userID, shareID, recipientID string, limit int) ([]RecipientActivityEvent, error)
	ListChallenges(ctx context.Context, userID, shareID string, limit int) ([]domain.Challenge, error)
	ListClaims(ctx context.Context, userID, shareID string) ([]domain.Claim, error)
	// RevokeClaim revokes a single claim. shareID scopes the operation:
	// the actor must own the share AND the claim must belong to it, so a
	// claim from another share cannot be revoked through a share the
	// actor happens to own.
	RevokeClaim(ctx context.Context, actorID, shareID, claimID string) error

	// ListAccessRequests returns the access requests for a share (creator
	// inspection). statusFilter "" returns every status; a non-empty value
	// scopes to that status.
	ListAccessRequests(ctx context.Context, userID, shareID, statusFilter string, limit int) ([]domain.AccessRequest, error)
	// ApproveAccessRequest adds (or reactivates) the requester as a
	// recipient under the share's existing restricted policy and marks the
	// request approved. It is NOT authorization: the requester must still
	// complete the normal verify -> claim -> delivery flow. The minted
	// passcode is returned exactly once.
	ApproveAccessRequest(ctx context.Context, userID, shareID, requestID string) (ApproveAccessRequestResult, error)
	// DenyAccessRequest marks a pending request denied; delivery stays
	// blocked (the requester is never made a recipient).
	DenyAccessRequest(ctx context.Context, userID, shareID, requestID, reason string) error
}

var _ RestrictedShareService = (*Service)(nil)

// UpdateSettingsInput describes the mutable knobs on an existing share.
// Only active shares can be mutated; expiry may be shortened or extended
// up to MaxTTL; max_downloads must be >= current download_count so a
// settings update cannot retroactively exhaust the share.
type UpdateSettingsInput struct {
	CreatorUserID string
	ShareID       string
	// ExpiresAt is applied verbatim when non-zero. Leave zero to skip.
	ExpiresAt time.Time
	// MaxDownloads, when non-nil, updates the cap. A nil pointer leaves
	// the cap unchanged — mirrors the HTTP PATCH body where a missing
	// key means "don't touch".
	MaxDownloads *int
}

// PublicDelivery is the narrow capability the share-gateway uses: given a
// token, return an open reader for the staged, plaintext content plus
// metadata to populate response headers. The caller is responsible for
// recording access and counting downloads.
type PublicDelivery interface {
	OpenByToken(ctx context.Context, rawToken string) (PublicPayload, error)
	OpenWithClaim(ctx context.Context, rawToken, rawClaim string) (PublicPayload, error)
	CountDownload(ctx context.Context, shareID string) (int, error)
	RecordAccess(ctx context.Context, shareID string, event domain.AccessEvent) error
	Resolve(ctx context.Context, rawToken string) (domain.Share, error)
	// LookupClaimRecipient resolves a raw claim cookie to its
	// recipient_id for access-row attribution on denial paths. Empty
	// when the cookie doesn't match a known claim.
	LookupClaimRecipient(ctx context.Context, rawClaim string) string
	// InspectClaim classifies a raw claim cookie on denial paths:
	// whether a cookie was presented at all, whether it matches a
	// known row, and if so why the row is no longer redeemable. Used
	// by the gateway to record stale-cookie denials with precise
	// reasons (claim_expired, claim_revoked, otp_required,
	// claim_missing) and proper recipient attribution.
	InspectClaim(ctx context.Context, rawClaim string) ClaimLookupResult
}

// PublicVerification is the gateway-facing slice of the restricted-share
// flow. The gateway uses it to answer POST /s/{token}/verify and
// POST /s/{token}/otp without knowing about the full service surface.
type PublicVerification interface {
	VerifyPasscode(ctx context.Context, rawToken, email, passcode string, rctx RemoteContext) (VerifyResult, error)
	SubmitOTP(ctx context.Context, rawToken, rawPendingClaim, otp string, rctx RemoteContext) (VerifyResult, error)
}

// PublicAccessRequests is the gateway-facing slice of the access-request
// flow. The gateway uses it to answer POST /s/{token}/request-access and
// GET /s/{token}/request-status without knowing the full service surface.
// It deliberately exposes only coarse status — never owner data, internal
// ids, decision metadata, secrets, or private file metadata.
type PublicAccessRequests interface {
	SubmitAccessRequest(ctx context.Context, rawToken, email, message string, rctx RemoteContext) (SubmitAccessRequestResult, error)
	AccessRequestStatus(ctx context.Context, rawToken, email string) (AccessRequestStatusResult, error)
}

type PublicPayload struct {
	Share        domain.Share
	ContentType  string
	OriginalName string
	Size         int64
	Body         io.ReadCloser
	// RecipientID is the restricted-share recipient whose claim
	// authorized this open. Empty on public-link shares; always
	// populated for restricted deliveries so the gateway can tag the
	// resulting share_access_events row with durable recipient
	// attribution.
	RecipientID string
}

// CreateShareInput is the authenticated caller's request body translated
// into service types.
type CreateShareInput struct {
	CreatorUserID string
	BoxID         string
	FileEntryID   string
	UnlockBMK     []byte // caller supplies the unwrapped BMK (from the unlock session) so the service can rewrap the blob under a share key.
	ExpiresAt     time.Time
	MaxDownloads  int
	// Policy is optional. Zero-value = public temporary-link share,
	// which preserves the original behavior. Setting Policy.AccessMode
	// to AccessModeRestricted switches the share to recipient-scoped
	// verified delivery.
	Policy SharePolicy
}

// SharePolicy controls whether a share is a public temporary link or a
// recipient-scoped restricted share. For restricted shares at least one
// recipient is required. Passcodes are generated server-side per recipient
// and returned once in CreateShareResult.RecipientPasscodes.
type SharePolicy struct {
	AccessMode      string
	DomainAllowlist []string
	RequireOTP      bool
	RecipientEmails []string
}

// CreateShareResult bundles the raw (one-shot) token that must be returned
// to the creator exactly once. For restricted shares, RecipientPasscodes
// maps recipient_id → raw passcode — also returned exactly once so the
// creator can transmit them out-of-band.
type CreateShareResult struct {
	Share              domain.Share
	RawToken           string
	Recipients         []domain.Recipient
	RecipientPasscodes map[string]string
}

// StageEngine is the persistence-layer operation that copies & rewraps a
// vault blob into a share-owned staged object.
type StageEngine interface {
	Stage(ctx context.Context, boxID, fileID string, unlockBMK []byte) (StagedPayload, error)
	Delete(ctx context.Context, shareID, storageKey string) error
	Open(ctx context.Context, storageKey string, wrappedShareKey, nonce []byte) (io.ReadCloser, error)
}

// StagedPayload is the result of staging the vault file for a share. The
// wrapped share key and nonce are what get persisted in share_objects.
type StagedPayload struct {
	StorageKey      string
	WrappedShareKey []byte
	Nonce           []byte
	SizeBytes       int64
	ContentType     string
	OriginalName    string
}

// FileLookup is the narrow vault dependency the share service needs: we only
// read metadata here; bytes are handled by the StageEngine.
type FileLookup interface {
	LookupFile(ctx context.Context, boxID, fileID string) (FileMeta, error)
}

// OTPDispatcher delivers a one-time code to a recipient over a channel that
// is SEPARATE from the HTTP response the recipient used to submit the
// passcode (e.g. email or SMS). Production deployments that enable
// require_otp MUST configure one: the OTP is a second factor, so handing it
// back in the verify response or printing it to a log would defeat the
// purpose. In local development DevModeOTPEcho can be set instead so the
// code is surfaced in the response for testing without external infra.
//
// Dispatch failures are surfaced to the caller (the recipient sees a
// generic verification error and can retry) — the code is never echoed as
// a fallback.
type OTPDispatcher interface {
	DispatchOTP(ctx context.Context, msg OTPMessage) error
}

// OTPMessage is the payload handed to an OTPDispatcher. It deliberately
// carries the raw code: the dispatcher is the one trusted component allowed
// to see it so it can transmit it out-of-band.
type OTPMessage struct {
	ShareID        string
	RecipientID    string
	RecipientEmail string
	Code           string
	ExpiresAt      time.Time
}

type FileMeta struct {
	Name        string
	ContentType string
	SizeBytes   int64
}

// Deps bundles the service's collaborators. Audit is optional (nil → silent).
// Recipient / Challenge / Claim repos are optional — when nil the service
// rejects restricted-share creation with a validation error so that
// deployments that have not run migration 015 cannot accidentally serve
// restricted shares.
type Deps struct {
	Shares     ShareRepository
	Objects    ShareObjectStore
	AccessLog  ShareAccessRecorder
	Recipients RecipientRepository
	Challenges ChallengeRepository
	Claims     ClaimRepository
	// AccessRequests persists owner-approved recipient access requests.
	// Optional — when nil the owner access-request routes 503 (like the
	// other restricted repos) and the gateway's public submit/status
	// endpoints are not registered.
	AccessRequests AccessRequestRepository
	Files          FileLookup
	Stage          StageEngine
	Tokens         TokenService
	Audit          auditapp.AuditService
	IDs            ids.IDGenerator
	Clock          clock.Clock
	// OTPDispatcher delivers one-time codes out-of-band for require_otp
	// shares. Nil disables out-of-band delivery — see DevModeOTPEcho.
	OTPDispatcher OTPDispatcher
	// DevModeOTPEcho, when true, surfaces the raw OTP in the verify
	// result/response for local development and tests. It must be false
	// in production-like environments; the binaries derive it from
	// APP_ENV (config.IsProductionLike). With both OTPDispatcher nil and
	// DevModeOTPEcho false, require_otp shares cannot be created (a
	// validation error is returned) so there is no silent half-working
	// state where OTPs leak into responses.
	DevModeOTPEcho bool
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	// ClaimTTL caps how long a recipient claim cookie is valid after a
	// successful verification. Defaults to 1h; the claim also cannot
	// outlive the share's own expiry.
	ClaimTTL time.Duration
	// OTPTTL caps how long a pending OTP row stays valid. Defaults to 10m.
	OTPTTL time.Duration
	// PasscodeRateLimit sets the max failed attempts per (share, ip) in
	// the PasscodeRateWindow. Defaults to 10.
	PasscodeRateLimit  int
	PasscodeRateWindow time.Duration
	// AccessRequestTTL caps how long a pending access request stays open
	// before the worker expires it. Defaults to 7 days.
	AccessRequestTTL time.Duration
	// AccessRequestRateLimit sets the max access-request submissions per
	// (share, ip) within AccessRequestRateWindow. Defaults to 5.
	AccessRequestRateLimit  int
	AccessRequestRateWindow time.Duration
}

// Service is the concrete ShareService + PublicDelivery impl.
type Service struct {
	deps Deps
}

var _ ShareService = (*Service)(nil)
var _ PublicDelivery = (*Service)(nil)
var _ PublicAccessRequests = (*Service)(nil)

func NewService(deps Deps) *Service {
	if deps.Clock == nil {
		deps.Clock = clock.RealClock{}
	}
	if deps.IDs == nil {
		deps.IDs = ids.RandomGenerator{}
	}
	if deps.DefaultTTL <= 0 {
		deps.DefaultTTL = 24 * time.Hour
	}
	if deps.MaxTTL <= 0 {
		deps.MaxTTL = 30 * 24 * time.Hour
	}
	if deps.ClaimTTL <= 0 {
		deps.ClaimTTL = time.Hour
	}
	if deps.OTPTTL <= 0 {
		deps.OTPTTL = 10 * time.Minute
	}
	if deps.PasscodeRateLimit <= 0 {
		deps.PasscodeRateLimit = 10
	}
	if deps.PasscodeRateWindow <= 0 {
		deps.PasscodeRateWindow = 15 * time.Minute
	}
	if deps.AccessRequestTTL <= 0 {
		deps.AccessRequestTTL = 7 * 24 * time.Hour
	}
	if deps.AccessRequestRateLimit <= 0 {
		deps.AccessRequestRateLimit = 5
	}
	if deps.AccessRequestRateWindow <= 0 {
		deps.AccessRequestRateWindow = time.Hour
	}
	return &Service{deps: deps}
}

func (s *Service) CreateShare(ctx context.Context, in CreateShareInput) (CreateShareResult, error) {
	if in.CreatorUserID == "" || in.BoxID == "" || in.FileEntryID == "" {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_request", "creator, box and file are required")
	}
	if len(in.UnlockBMK) == 0 {
		return CreateShareResult{}, platerr.New(platerr.CategoryAuth, "unlock_required", "an unlocked box is required to stage a share")
	}
	now := s.deps.Clock.Now().UTC()
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = now.Add(s.deps.DefaultTTL)
	}
	if in.ExpiresAt.Before(now.Add(time.Minute)) {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_expiry", "expiry must be in the future")
	}
	if in.ExpiresAt.After(now.Add(s.deps.MaxTTL)) {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_expiry", "expiry exceeds maximum share lifetime")
	}
	if in.MaxDownloads < 0 {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_max_downloads", "max_downloads must be >= 0")
	}
	if in.MaxDownloads == 0 {
		in.MaxDownloads = 10
	}
	// Confirm the file lives in the box (lightweight authz on top of
	// the unlock-session having already proved ownership of the box).
	if s.deps.Files != nil {
		if _, err := s.deps.Files.LookupFile(ctx, in.BoxID, in.FileEntryID); err != nil {
			return CreateShareResult{}, platerr.New(platerr.CategoryNotFound, "file_not_found", err.Error())
		}
	}
	raw, err := s.deps.Tokens.NewShareToken()
	if err != nil {
		return CreateShareResult{}, platerr.New(platerr.CategoryInternal, "token_gen", err.Error())
	}
	mode := in.Policy.AccessMode
	if mode == "" {
		mode = domain.AccessModePublic
	}
	if mode != domain.AccessModePublic && mode != domain.AccessModeRestricted {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_access_mode", "access_mode must be public or restricted")
	}
	allow := normalizeAllowlist(in.Policy.DomainAllowlist)
	// Reject contradictory policy combinations rather than silently
	// dropping recipient/domain/OTP options on a public link — that
	// would create a bearer share while the caller believes it is
	// recipient-scoped. The restricted-only knobs require
	// access_mode=restricted.
	if mode == domain.AccessModePublic && (len(in.Policy.RecipientEmails) > 0 || len(allow) > 0 || in.Policy.RequireOTP) {
		return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "invalid_policy",
			"recipient_emails, domain_allowlist, and require_otp require access_mode=restricted")
	}
	// normalizedEmails is the validated, de-duplicated recipient set for
	// restricted shares. Validate it BEFORE staging/persisting so a bad
	// policy fails fast with no share row, stage blob, or object left
	// behind (R16: no confusing partial state).
	var normalizedEmails []string
	if mode == domain.AccessModeRestricted {
		if s.deps.Recipients == nil || s.deps.Claims == nil || s.deps.Challenges == nil {
			return CreateShareResult{}, platerr.New(platerr.CategoryInternal, "restricted_not_configured", "restricted sharing is not configured on this deployment")
		}
		// require_otp depends on an out-of-band delivery channel. Refuse
		// to create such a share when neither a dispatcher nor the dev
		// echo is available, rather than silently issuing OTPs the
		// recipient could never receive (or that would leak into the
		// verify response in a production-like environment).
		if in.Policy.RequireOTP && s.deps.OTPDispatcher == nil && !s.deps.DevModeOTPEcho {
			return CreateShareResult{}, platerr.New(platerr.CategoryValidation, "otp_delivery_not_configured",
				"require_otp needs an out-of-band one-time-code delivery channel configured on this deployment")
		}
		normalizedEmails, err = normalizeRecipientEmails(allow, in.Policy.RecipientEmails)
		if err != nil {
			return CreateShareResult{}, err
		}
	}
	share := domain.Share{
		ID:                       s.deps.IDs.New("shr"),
		BoxID:                    in.BoxID,
		FileEntryID:              in.FileEntryID,
		TokenHash:                domain.HashShareToken(raw),
		Status:                   domain.StatusActive,
		AccessMode:               mode,
		RecipientDomainAllowlist: allow,
		RequireOTP:               in.Policy.RequireOTP,
		ExpiresAt:                in.ExpiresAt,
		MaxDownloads:             in.MaxDownloads,
		DownloadCount:            0,
		CreatedBy:                in.CreatorUserID,
		CreatedAt:                now,
	}

	// Stage encrypted bytes under a fresh per-share key BEFORE persisting,
	// so a failure leaves no orphan share row.
	staged, err := s.deps.Stage.Stage(ctx, in.BoxID, in.FileEntryID, in.UnlockBMK)
	if err != nil {
		return CreateShareResult{}, platerr.New(platerr.CategoryInternal, "stage_failed", err.Error())
	}
	obj := domain.ShareObject{
		ID:              s.deps.IDs.New("sho"),
		ShareID:         share.ID,
		StorageKey:      staged.StorageKey,
		WrappedShareKey: staged.WrappedShareKey,
		Nonce:           staged.Nonce,
		SizeBytes:       staged.SizeBytes,
		ContentType:     staged.ContentType,
		OriginalName:    staged.OriginalName,
		CreatedAt:       now,
	}
	if err := s.deps.Shares.Put(ctx, share); err != nil {
		_ = s.deps.Stage.Delete(ctx, share.ID, staged.StorageKey)
		return CreateShareResult{}, platerr.New(platerr.CategoryInternal, "persist_share", err.Error())
	}
	if err := s.deps.Objects.PutObject(ctx, obj); err != nil {
		_ = s.deps.Shares.Delete(ctx, share.ID)
		_ = s.deps.Stage.Delete(ctx, share.ID, staged.StorageKey)
		return CreateShareResult{}, platerr.New(platerr.CategoryInternal, "persist_object", err.Error())
	}
	result := CreateShareResult{Share: share, RawToken: raw}
	// Provision recipients BEFORE the terminal shares.created audit so a
	// create that ultimately fails leaves no trace: on a recipient
	// failure we synchronously unwind the share row, object row, and
	// stage blob (rather than parking a half-built share for the worker)
	// and never emit shares.created. Recipient provisioning is itself
	// atomic (PutBatch), so this branch persists either a complete
	// restricted share or nothing at all.
	if share.IsRestricted() {
		recs, passcodes, perr := s.provisionRecipients(ctx, share, normalizedEmails, in.CreatorUserID)
		if perr != nil {
			s.rollbackCreatedShare(ctx, share.ID, staged.StorageKey)
			return CreateShareResult{}, perr
		}
		result.Recipients = recs
		result.RecipientPasscodes = passcodes
	}
	s.emitAudit(ctx, auditdomain.EventShareCreated, auditdomain.SubjectTypeShare, share.ID, in.CreatorUserID, map[string]any{
		"box_id":        share.BoxID,
		"file_id":       share.FileEntryID,
		"expires_at":    share.ExpiresAt.Format(time.RFC3339),
		"max_downloads": share.MaxDownloads,
		"access_mode":   share.AccessMode,
		"require_otp":   share.RequireOTP,
	})
	return result, nil
}

// rollbackCreatedShare unwinds the persisted state of a half-built share
// (stage blob, object row, share row) when a later create step fails.
//
// Cleanup must survive its own partial failure. The worker locates a
// stage blob through the share -> object -> storage_key chain, so the
// row that points at a blob must NOT be deleted while the blob is still
// on disk — otherwise the blob is orphaned with nothing to reclaim it.
// We therefore:
//
//  1. stamp purge_requested first, so the share is immediately
//     non-deliverable and the worker's SharePurgeJob owns the teardown
//     if anything below fails;
//  2. delete the blob first (blobs-first, metadata-last — the same
//     ordering box-finalize uses). If the blob delete fails we stop and
//     leave the rows in place: purge_requested guarantees the worker
//     retries the blob delete via GetObject and converges, orphaning
//     nothing;
//  3. only once the blob is gone do we drop the object and share rows.
//     If a row delete then fails, the worker still converges it
//     (GetObject miss -> mark purged).
//
// The create returns an error in every branch, so the share is never
// served regardless of how far cleanup got.
func (s *Service) rollbackCreatedShare(ctx context.Context, shareID, storageKey string) {
	now := s.deps.Clock.Now().UTC()
	_ = s.deps.Shares.MarkPurgeRequested(ctx, shareID, now)
	if err := s.deps.Stage.Delete(ctx, shareID, storageKey); err != nil {
		return // worker reclaims via the still-present share+object rows
	}
	_ = s.deps.Objects.DeleteObject(ctx, shareID)
	_ = s.deps.Shares.Delete(ctx, shareID)
}

func normalizeAllowlist(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// UpdateSettings mutates expiry and/or max_downloads on an active share.
// Validation matches CreateShare's contract: future expiry within MaxTTL,
// max_downloads >= current download_count (never retroactively exhaust).
// Revoked/expired/purged shares are not eligible.
func (s *Service) UpdateSettings(ctx context.Context, in UpdateSettingsInput) (domain.Share, error) {
	share, err := s.Get(ctx, in.CreatorUserID, in.ShareID)
	if err != nil {
		return domain.Share{}, err
	}
	if share.Status != domain.StatusActive {
		return domain.Share{}, platerr.New(platerr.CategoryConflict, "share_not_active",
			"only active shares can be updated")
	}
	now := s.deps.Clock.Now().UTC()
	expires := share.ExpiresAt
	if !in.ExpiresAt.IsZero() {
		if in.ExpiresAt.Before(now.Add(time.Minute)) {
			return domain.Share{}, platerr.New(platerr.CategoryValidation, "invalid_expiry",
				"expires_at must be in the future")
		}
		if in.ExpiresAt.After(now.Add(s.deps.MaxTTL)) {
			return domain.Share{}, platerr.New(platerr.CategoryValidation, "invalid_expiry",
				"expires_at exceeds maximum share lifetime")
		}
		expires = in.ExpiresAt
	}
	maxDownloads := share.MaxDownloads
	if in.MaxDownloads != nil {
		v := *in.MaxDownloads
		if v < 0 {
			return domain.Share{}, platerr.New(platerr.CategoryValidation, "invalid_max_downloads",
				"max_downloads must be >= 0")
		}
		if v < share.DownloadCount {
			return domain.Share{}, platerr.New(platerr.CategoryValidation, "invalid_max_downloads",
				"max_downloads cannot be below current download_count")
		}
		maxDownloads = v
	}
	if expires.Equal(share.ExpiresAt) && maxDownloads == share.MaxDownloads {
		return share, nil
	}
	if err := s.deps.Shares.UpdateSettings(ctx, share.ID, expires, maxDownloads); err != nil {
		return domain.Share{}, platerr.New(platerr.CategoryInternal, "persist_update", err.Error())
	}
	share.ExpiresAt = expires
	share.MaxDownloads = maxDownloads
	s.emitAudit(ctx, auditdomain.EventShareSettingsEdited, auditdomain.SubjectTypeShare, share.ID, in.CreatorUserID, map[string]any{
		"expires_at":    expires.Format(time.RFC3339),
		"max_downloads": maxDownloads,
	})
	return share, nil
}

func (s *Service) ListByCreator(ctx context.Context, userID string) ([]domain.Share, error) {
	return s.deps.Shares.ListByCreator(ctx, userID)
}

func (s *Service) Get(ctx context.Context, userID, shareID string) (domain.Share, error) {
	share, err := s.deps.Shares.Get(ctx, shareID)
	if err != nil {
		return domain.Share{}, platerr.New(platerr.CategoryNotFound, "share_not_found", "share not found")
	}
	if share.CreatedBy != "" && share.CreatedBy != userID {
		return domain.Share{}, platerr.New(platerr.CategoryAuthz, "forbidden", "not the share creator")
	}
	return share, nil
}

func (s *Service) Revoke(ctx context.Context, userID, shareID string) error {
	share, err := s.deps.Shares.Get(ctx, shareID)
	if err != nil {
		return platerr.New(platerr.CategoryNotFound, "share_not_found", "share not found")
	}
	if share.CreatedBy != "" && share.CreatedBy != userID {
		return platerr.New(platerr.CategoryAuthz, "forbidden", "not the share creator")
	}
	if share.Status == domain.StatusRevoked || share.Status == domain.StatusPurged {
		return nil
	}
	now := s.deps.Clock.Now().UTC()
	// Stamp purge_requested first. If UpdateStatus fails afterwards the
	// worker still picks the row up on its next run — far better than
	// leaving an active share with no pending purge.
	if err := s.deps.Shares.MarkPurgeRequested(ctx, shareID, now); err != nil {
		return platerr.New(platerr.CategoryInternal, "persist_revoke", err.Error())
	}
	if err := s.deps.Shares.UpdateStatus(ctx, shareID, domain.StatusRevoked, now); err != nil {
		// purge_requested is set, so the worker's purge job will still
		// drop the stage blob; we surface the error so the caller can
		// retry the status flip.
		return platerr.New(platerr.CategoryInternal, "persist_revoke_status", err.Error())
	}
	s.emitAudit(ctx, auditdomain.EventShareRevoked, auditdomain.SubjectTypeShare, shareID, userID, map[string]any{"box_id": share.BoxID})
	return nil
}

func (s *Service) ResolveByToken(ctx context.Context, rawToken string) (domain.Share, error) {
	if rawToken == "" {
		return domain.Share{}, platerr.New(platerr.CategoryNotFound, "share_not_found", "share not found")
	}
	hash := domain.HashShareToken(rawToken)
	share, err := s.deps.Shares.GetByTokenHash(ctx, hash)
	if err != nil {
		return domain.Share{}, platerr.New(platerr.CategoryNotFound, "share_not_found", "share not found")
	}
	return share, nil
}

func (s *Service) ListAccess(ctx context.Context, userID, shareID string, limit int) ([]domain.AccessEvent, error) {
	share, err := s.Get(ctx, userID, shareID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.deps.AccessLog.ListByShare(ctx, share.ID, limit)
}

// ---- PublicDelivery ----

func (s *Service) Resolve(ctx context.Context, rawToken string) (domain.Share, error) {
	return s.ResolveByToken(ctx, rawToken)
}

// OpenByToken validates expiry/status/downloads and returns an open reader
// over the plaintext share object bytes. Caller must close the reader.
//
// For restricted shares the caller must have already exchanged a recipient
// passcode (and optional OTP) for a claim via VerifyPasscode/SubmitOTP, and
// must pass the resulting raw claim token via OpenWithClaim. Calling
// OpenByToken on a restricted share returns ErrClaimRequired so the
// gateway knows to redirect to the verify page.
func (s *Service) OpenByToken(ctx context.Context, rawToken string) (PublicPayload, error) {
	return s.OpenWithClaim(ctx, rawToken, "")
}

// OpenWithClaim is the restricted-aware variant of OpenByToken. When
// rawClaim is empty and the share is restricted, it returns
// ErrClaimRequired. When rawClaim is non-empty it must match an active
// (non-revoked, non-expired, non-OTP-pending) claim for the same share.
func (s *Service) OpenWithClaim(ctx context.Context, rawToken, rawClaim string) (PublicPayload, error) {
	share, err := s.ResolveByToken(ctx, rawToken)
	if err != nil {
		return PublicPayload{}, err
	}
	now := s.deps.Clock.Now().UTC()
	if !share.IsDeliverable(now) {
		return PublicPayload{}, platerr.New(platerr.CategoryNotFound, "share_not_available", "share is not available")
	}
	if share.MaxDownloads > 0 && share.DownloadCount >= share.MaxDownloads {
		return PublicPayload{}, platerr.New(platerr.CategoryNotFound, "share_exhausted", "share download cap reached")
	}
	var recipientID string
	if share.IsRestricted() {
		if s.deps.Claims == nil {
			return PublicPayload{}, platerr.New(platerr.CategoryInternal, "restricted_not_configured", "restricted sharing is not configured on this deployment")
		}
		if rawClaim == "" {
			return PublicPayload{}, ErrClaimRequired
		}
		claim, err := s.deps.Claims.GetByTokenHash(ctx, domain.HashClaimToken(rawClaim))
		if err != nil || claim.ShareID != share.ID {
			return PublicPayload{}, ErrClaimRequired
		}
		if !claim.IsActive(now) {
			return PublicPayload{}, ErrClaimRequired
		}
		// Defense in depth: a claim is only honored while its recipient
		// is still active. Recipient revocation already cascades a claim
		// revoke, but that is best-effort — re-checking the recipient row
		// here makes revocation effective immediately even if the cascade
		// was interrupted, so a revoked recipient can never redeem a
		// stale-but-unrevoked claim. The claim is the verified session;
		// the recipient row is the standing authorization behind it.
		if s.deps.Recipients != nil {
			rec, recErr := s.deps.Recipients.Get(ctx, claim.RecipientID)
			if recErr != nil || rec.RevokedAt != nil {
				return PublicPayload{}, ErrClaimRequired
			}
		}
		recipientID = claim.RecipientID
	}
	obj, err := s.deps.Objects.GetObject(ctx, share.ID)
	if err != nil {
		return PublicPayload{}, platerr.New(platerr.CategoryInternal, "object_missing", err.Error())
	}
	body, err := s.deps.Stage.Open(ctx, obj.StorageKey, obj.WrappedShareKey, obj.Nonce)
	if err != nil {
		return PublicPayload{}, platerr.New(platerr.CategoryInternal, "open_failed", err.Error())
	}
	return PublicPayload{
		Share:        share,
		ContentType:  obj.ContentType,
		OriginalName: obj.OriginalName,
		Size:         obj.SizeBytes,
		Body:         body,
		RecipientID:  recipientID,
	}, nil
}

// CountDownload bumps the download count and, when the new count hits
// MaxDownloads, stamps purge_requested and flips status to expired.
// The terminal `shares.expired` audit record is only emitted AFTER both
// writes actually succeed — a persistence failure leaves the share
// non-deliverable (IsDeliverable rejects on purge_requested, and the
// download cap is also reflected in the row) but without a misleading
// terminal audit row claiming convergence that never happened.
// Ordering: purge_requested first (so IsDeliverable blocks immediately),
// status second — matches the convention everywhere else.
func (s *Service) CountDownload(ctx context.Context, shareID string) (int, error) {
	now := s.deps.Clock.Now().UTC()
	count, err := s.deps.Shares.IncrementDownload(ctx, shareID, now)
	if err != nil {
		return 0, err
	}
	share, err := s.deps.Shares.Get(ctx, shareID)
	if err != nil {
		return count, nil
	}
	if share.MaxDownloads > 0 && count >= share.MaxDownloads {
		if markErr := s.deps.Shares.MarkPurgeRequested(ctx, shareID, now); markErr != nil {
			return count, nil
		}
		if statusErr := s.deps.Shares.UpdateStatus(ctx, shareID, domain.StatusExpired, now); statusErr != nil {
			return count, nil
		}
		s.emitAudit(ctx, auditdomain.EventShareExpired, auditdomain.SubjectTypeShare, shareID, "", map[string]any{
			"reason": "downloads_exhausted",
		})
	}
	return count, nil
}

// RecordAccess writes the access row and emits audit + a risk signal when
// risk_score >= elevated threshold.
func (s *Service) RecordAccess(ctx context.Context, shareID string, event domain.AccessEvent) error {
	if event.ID == "" {
		event.ID = s.deps.IDs.New("sha")
	}
	if event.AccessedAt.IsZero() {
		event.AccessedAt = s.deps.Clock.Now().UTC()
	}
	event.ShareID = shareID
	if err := s.deps.AccessLog.RecordAccess(ctx, event); err != nil {
		return err
	}
	eventType := auditdomain.EventShareAccessed
	if !event.Succeeded {
		eventType = auditdomain.EventShareAccessDenied
	}
	auditMeta := map[string]any{
		"remote_ip":  event.RemoteIP,
		"user_agent": event.UserAgent,
		"succeeded":  event.Succeeded,
		"risk_score": event.RiskScore,
	}
	if event.RecipientID != "" {
		// Surfaces recipient attribution on both shares.accessed and
		// shares.access_denied so the audit UI's recipient filter
		// returns the full restricted-delivery lifecycle, not just
		// the verification attempts in share_challenges.
		auditMeta["recipient_id"] = event.RecipientID
	}
	s.emitAudit(ctx, eventType, auditdomain.SubjectTypeShare, shareID, "", auditMeta)
	if s.deps.Audit != nil && event.RiskScore >= 40 {
		_ = s.deps.Audit.RecordSignal(ctx, auditdomain.RiskSignal{
			SignalType:  "share.elevated_risk_access",
			Severity:    severityFor(event.RiskScore),
			SubjectType: auditdomain.SubjectTypeShare,
			SubjectID:   shareID,
			Metadata: map[string]any{
				"remote_ip":  event.RemoteIP,
				"user_agent": event.UserAgent,
				"risk_score": event.RiskScore,
			},
		})
	}
	return nil
}

func severityFor(score int) string {
	switch {
	case score >= 70:
		return auditdomain.SeverityHigh
	case score >= 40:
		return auditdomain.SeverityElevated
	case score >= 20:
		return auditdomain.SeverityLow
	default:
		return auditdomain.SeverityInfo
	}
}

func (s *Service) emitAudit(ctx context.Context, eventType, subjectType, subjectID, actorID string, meta map[string]any) {
	if s.deps.Audit == nil {
		return
	}
	_ = s.deps.Audit.Record(ctx, auditdomain.AuditEvent{
		EventType:   eventType,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		ActorID:     actorID,
		Metadata:    meta,
		OccurredAt:  s.deps.Clock.Now().UTC(),
	})
}

// PurgeByBox deletes every stage blob for shares belonging to boxID.
// Called by the vault service's box-deletion hook before the pg
// cascade removes the share_objects rows; best-effort, errors are
// returned but the vault delete continues regardless.
// PurgeByBox best-effort-cleans up every share owned by the deleted box.
// Each share is stamped `purge_requested_at` so the public delivery
// path immediately refuses it (see Share.IsDeliverable) and the
// worker's SharePurgeJob will finalize it. We also attempt an inline
// stage-blob delete so typical deletions converge on the same tick —
// but we do NOT emit a terminal `shares.purged` audit here. That
// record is the responsibility of SharePurgeJob.runOne, which only
// emits AFTER UpdateStatus(StatusPurged) succeeds and the stored model
// has actually converged. Emitting early would mean the audit log
// claims a share is purged while its `status` column still reads
// `active` or `revoked`.
//
// The first concrete error from the stage engine is returned so the
// caller can surface / audit it; the loop continues so one bad share
// doesn't block the others.
func (s *Service) PurgeByBox(ctx context.Context, boxID string) error {
	shares, err := s.deps.Shares.ListByBox(ctx, boxID)
	if err != nil {
		return err
	}
	now := s.deps.Clock.Now().UTC()
	var firstErr error
	for _, sh := range shares {
		_ = s.deps.Shares.MarkPurgeRequested(ctx, sh.ID, now)
		obj, err := s.deps.Objects.GetObject(ctx, sh.ID)
		if err != nil {
			// No object row for this share; nothing on disk to delete.
			continue
		}
		if derr := s.deps.Stage.Delete(ctx, sh.ID, obj.StorageKey); derr != nil {
			if firstErr == nil {
				firstErr = derr
			}
			// Non-terminal record so operators can see the partial —
			// the share is NOT audited as purged yet; the worker emits
			// that only after status actually flips.
			s.emitAudit(ctx, auditdomain.EventSharePurgePartial, auditdomain.SubjectTypeShare, sh.ID, "", map[string]any{
				"reason": "box_deleted", "box_id": boxID, "error": derr.Error(),
			})
		}
	}
	return firstErr
}

// ErrShareNotFound is returned by ResolveByToken when no matching active
// share exists. Kept exported for callers that want to distinguish it
// from internal errors.
var ErrShareNotFound = errors.New("share not found")

// ErrClaimRequired is returned by OpenWithClaim when a restricted share
// has no active claim present — the gateway translates this into a 401
// redirect to the verify page.
var ErrClaimRequired = errors.New("share claim required")
