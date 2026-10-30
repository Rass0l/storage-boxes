package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/enrichment"
	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	vaultapi "github.com/Rass0l/storage-boxes/internal/vault/api"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
)

// Deps is the wiring for the authenticated share management API.
// Public-share delivery lives in the share-gateway binary via
// RegisterPublicRoutes. When Deps is zero-valued, only a minimal stub is
// registered so cross-package tests still return 200 for /api/v1/shares.
type Deps struct {
	Service app.ShareService
	// Restricted exposes the recipient/verification surface. Optional —
	// when nil, the restricted-share API routes return 503 but public
	// shares continue to work.
	Restricted    app.RestrictedShareService
	Public        app.PublicDelivery
	Vault         *vaultapp.Service
	Identity      *identityapp.Service
	PublicBaseURL string
	// TrustedProxies controls X-Forwarded-For handling for public share
	// access records. Only peers whose RemoteAddr matches one of these
	// CIDRs/IPs are allowed to override the recorded remote_ip. Optional.
	TrustedProxies []string
	// RiskScorer computes a 0–100 risk score for each public access. If
	// nil, the HeuristicRiskScorer is used.
	RiskScorer enrichment.RiskScorer
	// CountryLookup resolves client IPs to a two-letter code that lands
	// in `share_access_events.country_code`. If nil,
	// DefaultCountryLookup is used (classifies loopback / private,
	// leaves public unresolved). Production deployments wire a real
	// GeoIP provider (MaxMind, ip2location, Cloudflare CF-IPCountry
	// header) by supplying their own CountryLookup.
	CountryLookup enrichment.CountryLookup
}

// RegisterRoutes wires authenticated share endpoints onto mux. Public share
// delivery is registered separately via RegisterPublicRoutes (share-gateway).
func RegisterRoutes(mux *http.ServeMux, deps ...Deps) {
	var d Deps
	if len(deps) > 0 {
		d = deps[0]
	}
	if d.Service == nil || d.Identity == nil || d.Vault == nil {
		registerStubs(mux)
		return
	}
	h := &handlers{deps: d}

	authed := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(d.Identity, next)
	}
	writing := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(d.Identity,
			identityapi.RequireCSRF(vaultapi.RequireUnlockSession(d.Vault, next)))
	}
	mutating := func(next http.Handler) http.Handler {
		return identityapi.RequireAuth(d.Identity, identityapi.RequireCSRF(next))
	}
	mux.Handle("GET /api/v1/shares", authed(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/shares", writing(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/shares/{id}", authed(http.HandlerFunc(h.get)))
	mux.Handle("PATCH /api/v1/shares/{id}", mutating(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/shares/{id}", mutating(http.HandlerFunc(h.revoke)))
	mux.Handle("GET /api/v1/shares/{id}/access", authed(http.HandlerFunc(h.listAccess)))

	// Restricted-share surface. All require auth + CSRF; creator-only via
	// service Get-ownership check. These 503 when deps.Restricted is nil.
	mux.Handle("POST /api/v1/shares/{id}/recipients", mutating(http.HandlerFunc(h.addRecipients)))
	mux.Handle("GET /api/v1/shares/{id}/recipients", authed(http.HandlerFunc(h.listRecipients)))
	mux.Handle("POST /api/v1/shares/{id}/recipients/{rid}/rotate", mutating(http.HandlerFunc(h.rotateRecipient)))
	mux.Handle("DELETE /api/v1/shares/{id}/recipients/{rid}", mutating(http.HandlerFunc(h.revokeRecipient)))
	mux.Handle("GET /api/v1/shares/{id}/recipients/{rid}/activity", authed(http.HandlerFunc(h.recipientActivity)))
	mux.Handle("GET /api/v1/shares/{id}/challenges", authed(http.HandlerFunc(h.listChallenges)))
	mux.Handle("GET /api/v1/shares/{id}/claims", authed(http.HandlerFunc(h.listClaims)))
	mux.Handle("DELETE /api/v1/shares/{id}/claims/{cid}", mutating(http.HandlerFunc(h.revokeClaimHandler)))

	// Owner-approved recipient access requests. Inspection is auth-only;
	// approve/deny mutate so they require CSRF. Creator-only via the
	// service Get-ownership check; 503 when deps.Restricted is nil.
	mux.Handle("GET /api/v1/shares/{id}/access-requests", authed(http.HandlerFunc(h.listAccessRequests)))
	mux.Handle("POST /api/v1/shares/{id}/access-requests/{arid}/approve", mutating(http.HandlerFunc(h.approveAccessRequest)))
	mux.Handle("POST /api/v1/shares/{id}/access-requests/{arid}/deny", mutating(http.HandlerFunc(h.denyAccessRequest)))
}

// RegisterPublicRoutes wires the unauthenticated GET /s/{token} endpoint
// that serves staged share bytes. Must be registered on the share-gateway
// binary; do NOT call this from the api binary.
func RegisterPublicRoutes(mux *http.ServeMux, deps Deps) {
	if deps.Public == nil {
		mux.HandleFunc("GET /s/{token}", func(w http.ResponseWriter, r *http.Request) {
			_ = r
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"share_service_down","message":"share delivery not configured"}}`))
		})
		return
	}
	h := &publicHandlers{deps: deps}
	mux.HandleFunc("GET /s/{token}", h.download)
	mux.HandleFunc("HEAD /s/{token}", h.head)
}

func registerStubs(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[],"note":"share service not configured"}`))
	})
	mux.HandleFunc("POST /api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"share_service_down","message":"share service not configured"}}`))
	})
	mux.HandleFunc("GET /s/{token}", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"share_service_down","message":"share delivery not configured"}}`))
	})
}

type handlers struct{ deps Deps }

func (h *handlers) list(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	shares, err := h.deps.Service.ListByCreator(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]ShareResponse, 0, len(shares))
	for _, s := range shares {
		out = append(out, toShareResponse(s))
	}
	writeJSON(w, http.StatusOK, ShareListResponse{Items: out})
}

func (h *handlers) create(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	uc, _ := vaultapi.UnlockFrom(r.Context())
	var req CreateShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	if req.BoxID == "" {
		req.BoxID = r.URL.Query().Get("box_id")
	}
	if req.BoxID == "" || req.BoxID != uc.BoxID {
		writeError(w, http.StatusForbidden, "unlock_wrong_box", "unlock session must match body.box_id")
		return
	}
	ttl := time.Duration(req.ExpirySeconds) * time.Second
	if req.ExpirySeconds <= 0 {
		ttl = 24 * time.Hour
	}
	in := app.CreateShareInput{
		CreatorUserID: user.ID,
		BoxID:         req.BoxID,
		FileEntryID:   req.FileEntryID,
		UnlockBMK:     uc.BMK,
		ExpiresAt:     time.Now().UTC().Add(ttl),
		MaxDownloads:  req.MaxDownloads,
	}
	// Always thread the policy fields through (not gated on access_mode
	// being set) so the service can reject contradictory combinations —
	// e.g. recipient_emails supplied without access_mode=restricted —
	// rather than silently dropping them and issuing a bearer link.
	in.Policy = app.SharePolicy{
		AccessMode:      req.AccessMode,
		DomainAllowlist: req.DomainAllowlist,
		RequireOTP:      req.RequireOTP,
		RecipientEmails: req.RecipientEmails,
	}
	result, err := h.deps.Service.CreateShare(r.Context(), in)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	resp := CreateShareResponse{
		ID:              result.Share.ID,
		Token:           result.RawToken,
		URL:             shareURL(h.deps.PublicBaseURL, result.RawToken),
		BoxID:           result.Share.BoxID,
		FileEntryID:     result.Share.FileEntryID,
		Status:          result.Share.Status,
		ExpiresAt:       result.Share.ExpiresAt.Format(time.RFC3339),
		MaxDownloads:    result.Share.MaxDownloads,
		DownloadCount:   result.Share.DownloadCount,
		CreatedAt:       result.Share.CreatedAt.Format(time.RFC3339),
		Deliverable:     result.Share.IsDeliverable(time.Now().UTC()),
		AccessMode:      result.Share.AccessMode,
		RequireOTP:      result.Share.RequireOTP,
		DomainAllowlist: result.Share.RecipientDomainAllowlist,
	}
	if result.Share.PurgeRequestedAt != nil {
		resp.PurgeRequestedAt = result.Share.PurgeRequestedAt.Format(time.RFC3339)
	}
	for _, rec := range result.Recipients {
		resp.Recipients = append(resp.Recipients, RecipientInviteDTO{
			RecipientDTO: toRecipientDTO(rec),
			Passcode:     result.RecipientPasscodes[rec.ID],
		})
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	share, err := h.deps.Service.Get(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toShareResponse(share))
}

// update is PATCH /api/v1/shares/{id}. Applies expiry and/or max_downloads
// to an active share. Missing fields are treated as "leave unchanged" —
// the caller can shorten expiry without supplying max_downloads.
func (h *handlers) update(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	var req UpdateShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	in := app.UpdateSettingsInput{
		CreatorUserID: user.ID,
		ShareID:       r.PathValue("id"),
		MaxDownloads:  req.MaxDownloads,
	}
	if req.ExpirySeconds != 0 {
		in.ExpiresAt = time.Now().UTC().Add(time.Duration(req.ExpirySeconds) * time.Second)
	}
	share, err := h.deps.Service.UpdateSettings(r.Context(), in)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toShareResponse(share))
}

func (h *handlers) revoke(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	if err := h.deps.Service.Revoke(r.Context(), user.ID, r.PathValue("id")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listAccess(w http.ResponseWriter, r *http.Request) {
	user, _ := identityapi.UserFrom(r.Context())
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := h.deps.Service.ListAccess(r.Context(), user.ID, r.PathValue("id"), limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	items := make([]AccessEventResponse, 0, len(events))
	for _, e := range events {
		items = append(items, AccessEventResponse{
			ID:          e.ID,
			RecipientID: e.RecipientID,
			RemoteIP:    e.RemoteIP,
			UserAgent:   e.UserAgent,
			Referer:     e.Referer,
			Succeeded:   e.Succeeded,
			AccessedAt:  e.AccessedAt.Format(time.RFC3339),
			RiskScore:   e.RiskScore,
			CountryCode: e.CountryCode,
		})
	}
	writeJSON(w, http.StatusOK, AccessEventListResponse{Items: items})
}

func toShareResponse(s domain.Share) ShareResponse {
	out := ShareResponse{
		ID:              s.ID,
		BoxID:           s.BoxID,
		FileEntryID:     s.FileEntryID,
		Status:          s.Status,
		ExpiresAt:       s.ExpiresAt.Format(time.RFC3339),
		MaxDownloads:    s.MaxDownloads,
		DownloadCount:   s.DownloadCount,
		CreatedAt:       s.CreatedAt.Format(time.RFC3339),
		Deliverable:     s.IsDeliverable(time.Now().UTC()),
		AccessMode:      s.AccessMode,
		RequireOTP:      s.RequireOTP,
		DomainAllowlist: s.RecipientDomainAllowlist,
	}
	if out.AccessMode == "" {
		out.AccessMode = domain.AccessModePublic
	}
	if s.RevokedAt != nil {
		out.RevokedAt = s.RevokedAt.Format(time.RFC3339)
	}
	if s.PurgeRequestedAt != nil {
		out.PurgeRequestedAt = s.PurgeRequestedAt.Format(time.RFC3339)
	}
	return out
}

func toRecipientDTO(r domain.Recipient) RecipientDTO {
	out := RecipientDTO{
		ID:              r.ID,
		ShareID:         r.ShareID,
		Email:           r.Email,
		EmailNormalized: r.EmailNormalized,
		FailedAttempts:  r.FailedAttempts,
		CreatedAt:       r.CreatedAt.Format(time.RFC3339),
	}
	if r.VerifiedAt != nil {
		out.VerifiedAt = r.VerifiedAt.Format(time.RFC3339)
	}
	if r.RevokedAt != nil {
		out.RevokedAt = r.RevokedAt.Format(time.RFC3339)
	}
	return out
}

func toChallengeDTO(c domain.Challenge) ChallengeDTO {
	return ChallengeDTO{
		ID:          c.ID,
		ShareID:     c.ShareID,
		RecipientID: c.RecipientID,
		Kind:        c.Kind,
		Succeeded:   c.Succeeded,
		Reason:      c.Reason,
		RemoteIP:    c.RemoteIP,
		UserAgent:   c.UserAgent,
		AttemptedAt: c.AttemptedAt.Format(time.RFC3339),
		RiskScore:   c.RiskScore,
		CountryCode: c.CountryCode,
	}
}

func toClaimDTO(c domain.Claim) ClaimDTO {
	out := ClaimDTO{
		ID:          c.ID,
		ShareID:     c.ShareID,
		RecipientID: c.RecipientID,
		IssuedAt:    c.IssuedAt.Format(time.RFC3339),
		ExpiresAt:   c.ExpiresAt.Format(time.RFC3339),
		OTPPending:  c.OTPPending,
		RemoteIP:    c.RemoteIP,
		UserAgent:   c.UserAgent,
	}
	if c.RevokedAt != nil {
		out.RevokedAt = c.RevokedAt.Format(time.RFC3339)
	}
	return out
}

func toAccessRequestDTO(ar domain.AccessRequest) AccessRequestDTO {
	out := AccessRequestDTO{
		ID:              ar.ID,
		ShareID:         ar.ShareID,
		RequesterEmail:  ar.RequesterEmail,
		RequesterDomain: ar.RequesterDomain,
		Message:         ar.Message,
		Status:          ar.Status,
		RecipientID:     ar.RecipientID,
		DecidedBy:       ar.DecidedBy,
		DecisionReason:  ar.DecisionReason,
		RemoteIP:        ar.RemoteIP,
		UserAgent:       ar.UserAgent,
		CountryCode:     ar.CountryCode,
		RiskScore:       ar.RiskScore,
		CreatedAt:       ar.CreatedAt.Format(time.RFC3339),
	}
	if ar.DecidedAt != nil {
		out.DecidedAt = ar.DecidedAt.Format(time.RFC3339)
	}
	if ar.ExpiresAt != nil {
		out.ExpiresAt = ar.ExpiresAt.Format(time.RFC3339)
	}
	return out
}

func shareURL(base, token string) string {
	if base == "" {
		return "/s/" + token
	}
	return base + "/s/" + token
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(platerr.HTTPErrorResponse{
		Error: platerr.ErrorBody{Code: code, Message: msg},
	})
}

func writeDomainError(w http.ResponseWriter, err error) {
	if de, ok := err.(*platerr.DomainError); ok {
		writeError(w, platerr.HTTPStatus(de), de.Code, de.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal", err.Error())
}

// publicHandlers serves unauthenticated /s/{token} requests.
type publicHandlers struct{ deps Deps }

func (h *publicHandlers) download(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	h.serve(w, r, token, serveDownload)
}

// head answers HEAD probes without incrementing download_count and without
// recording a successful-access row. It still records a denied-access row
// when the share is unavailable so operators can see failed probes.
func (h *publicHandlers) head(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	h.serve(w, r, token, serveProbe)
}

type serveMode int

const (
	serveDownload serveMode = iota // GET: body streamed, count++, access row logged.
	serveProbe                     // HEAD: headers only, count unchanged, no success row.
)

func (h *publicHandlers) serve(w http.ResponseWriter, r *http.Request, token string, mode serveMode) {
	rc := enrichment.Extract(r, h.deps.TrustedProxies)
	scorer := h.deps.RiskScorer
	if scorer == nil {
		scorer = enrichment.HeuristicRiskScorer{}
	}
	country := h.deps.CountryLookup
	if country == nil {
		country = enrichment.DefaultCountryLookup{}
	}
	cc := country.Lookup(rc.RemoteIP)

	payload, err := h.deps.Public.OpenByToken(r.Context(), token)
	if err != nil {
		share, resolveErr := h.deps.Public.Resolve(r.Context(), token)
		if resolveErr == nil {
			score, _ := scorer.Score(map[string]string{
				"remote_ip":          rc.RemoteIP,
				"user_agent":         rc.UserAgent,
				"new_ip_for_subject": "false",
				"near_download_cap":  "true", // denied accesses often trail exhaustion
			})
			_ = h.deps.Public.RecordAccess(r.Context(), share.ID, domain.AccessEvent{
				Succeeded:   false,
				RemoteIP:    rc.RemoteIP,
				UserAgent:   rc.UserAgent,
				Referer:     rc.Referer,
				RiskScore:   score,
				CountryCode: cc,
				Metadata: map[string]any{
					"reason":     classifyShareError(err),
					"request_id": rc.RequestID,
				},
			})
		}
		writeDomainError(w, err)
		return
	}
	defer payload.Body.Close()

	// near-cap heuristic: we just passed OpenByToken's cap check, but the
	// fresh download will bump the count. Flag high-risk when this is the
	// final permitted read.
	nearCap := "false"
	if payload.Share.MaxDownloads > 0 && payload.Share.DownloadCount+1 >= payload.Share.MaxDownloads {
		nearCap = "true"
	}
	score, _ := scorer.Score(map[string]string{
		"remote_ip":          rc.RemoteIP,
		"user_agent":         rc.UserAgent,
		"new_ip_for_subject": "false",
		"near_download_cap":  nearCap,
	})

	ct := payload.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if payload.OriginalName != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+payload.OriginalName+`"`)
	}
	if payload.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(payload.Size, 10))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	// Probe (HEAD) stops here: no body, no counter bump, no success row.
	// RFC 9110 § 9.3.2 — HEAD must be identical to GET headers without
	// the body, and implementations "SHOULD NOT have side effects".
	if mode == serveProbe {
		return
	}

	// Stream the body. Only count + audit-success when io.Copy actually
	// finishes cleanly. A mid-stream failure (client disconnect, stage
	// read error, short write) must record a denied-access row and
	// leave `download_count` untouched — otherwise the share looks like
	// it served successfully to someone who got a partial or no body.
	n, copyErr := io.Copy(w, payload.Body)
	shortWrite := payload.Size > 0 && n < payload.Size
	if copyErr != nil || shortWrite {
		reason := "stream_interrupted"
		if copyErr != nil {
			reason = classifyShareError(copyErr)
		} else if shortWrite {
			reason = "short_write"
		}
		_ = h.deps.Public.RecordAccess(r.Context(), payload.Share.ID, domain.AccessEvent{
			Succeeded:   false,
			RemoteIP:    rc.RemoteIP,
			UserAgent:   rc.UserAgent,
			Referer:     rc.Referer,
			RiskScore:   score,
			CountryCode: cc,
			Metadata: map[string]any{
				"reason":        reason,
				"bytes_written": n,
				"request_id":    rc.RequestID,
				"method":        r.Method,
			},
		})
		return
	}

	// Full body delivered. Bump counter + record success. Note:
	// IncrementDownload happens AFTER the stream finishes so a partial
	// read never looks like a successful download.
	_, _ = h.deps.Public.CountDownload(r.Context(), payload.Share.ID)
	_ = h.deps.Public.RecordAccess(r.Context(), payload.Share.ID, domain.AccessEvent{
		Succeeded:   true,
		RemoteIP:    rc.RemoteIP,
		UserAgent:   rc.UserAgent,
		Referer:     rc.Referer,
		RiskScore:   score,
		CountryCode: cc,
		Metadata: map[string]any{
			"request_id":    rc.RequestID,
			"method":        r.Method,
			"bytes_written": n,
		},
	})
}

// ---- restricted-share handlers ----

func (h *handlers) requireRestricted(w http.ResponseWriter) bool {
	if h.deps.Restricted == nil {
		writeError(w, http.StatusServiceUnavailable, "restricted_not_configured",
			"restricted sharing is not configured on this deployment")
		return false
	}
	return true
}

func (h *handlers) addRecipients(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	var req AddRecipientsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	invites, err := h.deps.Restricted.AddRecipients(r.Context(), app.AddRecipientsInput{
		ActorUserID: user.ID,
		ShareID:     r.PathValue("id"),
		Emails:      req.Emails,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	resp := AddRecipientsResponse{Items: make([]RecipientInviteDTO, 0, len(invites))}
	for _, inv := range invites {
		resp.Items = append(resp.Items, RecipientInviteDTO{
			RecipientDTO: toRecipientDTO(inv.Recipient),
			Passcode:     inv.Passcode,
		})
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *handlers) listRecipients(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	recs, err := h.deps.Restricted.ListRecipients(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	out := RecipientListResponse{Items: make([]RecipientDTO, 0, len(recs))}
	for _, rec := range recs {
		out.Items = append(out.Items, toRecipientDTO(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) rotateRecipient(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	rec, raw, err := h.deps.Restricted.RotateRecipientPasscode(r.Context(), user.ID, r.PathValue("id"), r.PathValue("rid"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, RotatePasscodeResponse{
		RecipientDTO: toRecipientDTO(rec),
		Passcode:     raw,
	})
}

func (h *handlers) revokeRecipient(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	if err := h.deps.Restricted.RevokeRecipient(r.Context(), user.ID, r.PathValue("id"), r.PathValue("rid")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) recipientActivity(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	limit := parseLimit(r, 100, 500)
	events, err := h.deps.Restricted.ListRecipientActivity(r.Context(), user.ID, r.PathValue("id"), r.PathValue("rid"), limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	out := RecipientActivityListResponse{Items: make([]RecipientActivityDTO, 0, len(events))}
	for _, e := range events {
		out.Items = append(out.Items, RecipientActivityDTO{
			Kind:           e.Kind,
			ID:             e.ID,
			ShareID:        e.ShareID,
			RecipientID:    e.RecipientID,
			OccurredAt:     e.OccurredAt.Format(time.RFC3339),
			Succeeded:      e.Succeeded,
			Reason:         e.Reason,
			ChallengeKind:  e.ChallengeKind,
			LifecycleEvent: e.LifecycleEvent,
			ActorID:        e.ActorID,
			RemoteIP:       e.RemoteIP,
			UserAgent:      e.UserAgent,
			CountryCode:    e.CountryCode,
			RiskScore:      e.RiskScore,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) listChallenges(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	limit := parseLimit(r, 100, 500)
	chs, err := h.deps.Restricted.ListChallenges(r.Context(), user.ID, r.PathValue("id"), limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	out := ChallengeListResponse{Items: make([]ChallengeDTO, 0, len(chs))}
	for _, c := range chs {
		out.Items = append(out.Items, toChallengeDTO(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) listClaims(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	claims, err := h.deps.Restricted.ListClaims(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	out := ClaimListResponse{Items: make([]ClaimDTO, 0, len(claims))}
	for _, c := range claims {
		out.Items = append(out.Items, toClaimDTO(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) revokeClaimHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	// RevokeClaim enforces both share ownership and that the claim
	// belongs to {id}, so a claim from another share can't be revoked
	// through a share this user happens to own.
	if err := h.deps.Restricted.RevokeClaim(r.Context(), user.ID, r.PathValue("id"), r.PathValue("cid")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listAccessRequests(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	limit := parseLimit(r, 100, 500)
	status := r.URL.Query().Get("status")
	shareID := r.PathValue("id")
	reqs, err := h.deps.Restricted.ListAccessRequests(r.Context(), user.ID, shareID, status, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// Project each linked recipient's CURRENT state so an approved request
	// whose recipient was later revoked is not shown as live access. This is
	// a read-side annotation — the request's historical `status` is left
	// intact (compliance), recipient_state carries current truth. One extra
	// ListRecipients call, only when some request actually links a recipient.
	recState := map[string]string{}
	needRecs := false
	for _, ar := range reqs {
		if ar.RecipientID != "" {
			needRecs = true
			break
		}
	}
	if needRecs {
		if recs, rerr := h.deps.Restricted.ListRecipients(r.Context(), user.ID, shareID); rerr == nil {
			byID := make(map[string]domain.Recipient, len(recs))
			for _, rec := range recs {
				byID[rec.ID] = rec
			}
			for _, ar := range reqs {
				if ar.RecipientID == "" {
					continue
				}
				switch rec, ok := byID[ar.RecipientID]; {
				case !ok:
					recState[ar.RecipientID] = "missing"
				case rec.RevokedAt != nil:
					recState[ar.RecipientID] = "revoked"
				default:
					recState[ar.RecipientID] = "active"
				}
			}
		}
	}
	out := AccessRequestListResponse{Items: make([]AccessRequestDTO, 0, len(reqs))}
	for _, ar := range reqs {
		dto := toAccessRequestDTO(ar)
		dto.RecipientState = recState[ar.RecipientID]
		out.Items = append(out.Items, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) approveAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	res, err := h.deps.Restricted.ApproveAccessRequest(r.Context(), user.ID, r.PathValue("id"), r.PathValue("arid"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AccessRequestApproveResponse{
		Request:     toAccessRequestDTO(res.Request),
		Recipient:   toRecipientDTO(res.Recipient),
		Passcode:    res.Passcode,
		Reactivated: res.Reactivated,
	})
}

func (h *handlers) denyAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !h.requireRestricted(w) {
		return
	}
	user, _ := identityapi.UserFrom(r.Context())
	var req DenyAccessRequestRequest
	// Body is optional; ignore decode errors so a bodyless deny still works.
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.deps.Restricted.DenyAccessRequest(r.Context(), user.ID, r.PathValue("id"), r.PathValue("arid"), req.Reason); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseLimit(r *http.Request, def, max int) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > max {
				return max
			}
			return n
		}
	}
	return def
}

// classifyShareError maps DomainError codes to a stable audit reason.
func classifyShareError(err error) string {
	if de, ok := err.(*platerr.DomainError); ok {
		return de.Code
	}
	return strings.ToLower(strings.ReplaceAll(err.Error(), " ", "_"))
}
