package api

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/Rass0l/storage-boxes/internal/audit/enrichment"
	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// ShareClaimCookieName is the HttpOnly cookie that carries the raw claim
// token back to the gateway on subsequent downloads. It is scoped per
// share via Path=/s/<token> so one recipient's claim can't ride on
// another share.
const ShareClaimCookieName = "sb_share_claim"

// GatewayDeps augments Deps with the restricted-verification service so
// the gateway can serve /s/{token}/verify and /s/{token}/otp. Leaving
// Verification nil keeps the gateway in legacy-only mode.
type GatewayDeps struct {
	Deps
	Verification app.PublicVerification
	// AccessRequests, when set, enables the public access-request endpoints
	// (/s/{token}/request-access, /s/{token}/request-status). Nil leaves
	// them unregistered (legacy deployments without migration 017).
	AccessRequests app.PublicAccessRequests
	// SecureCookies controls the Secure attribute on the claim cookie.
	// Production HTTPS deployments set it true (derived from
	// config.RequireTLS / APP_ENV); local HTTP development leaves it
	// false so the cookie is actually stored over http://localhost.
	// HttpOnly + SameSite=Strict + per-share Path scoping apply in both
	// modes — only Secure is environment-dependent.
	SecureCookies bool
}

// RegisterGatewayRoutes wires the public download endpoint and, when
// Verification is configured, the restricted-share verify/otp/revoke
// endpoints onto mux. Call this from the share-gateway binary instead of
// RegisterPublicRoutes when you want restricted delivery.
func RegisterGatewayRoutes(mux *http.ServeMux, deps GatewayDeps) {
	if deps.Public == nil {
		RegisterPublicRoutes(mux, deps.Deps)
		return
	}
	pub := &publicHandlers{deps: deps.Deps}
	g := &gatewayRestrictedHandlers{deps: deps, pub: pub}
	mux.HandleFunc("GET /s/{token}", func(w http.ResponseWriter, r *http.Request) {
		g.downloadOrVerify(w, r, serveDownload)
	})
	mux.HandleFunc("HEAD /s/{token}", func(w http.ResponseWriter, r *http.Request) {
		g.downloadOrVerify(w, r, serveProbe)
	})
	if deps.Verification != nil {
		mux.HandleFunc("GET /s/{token}/verify", g.verifyPage)
		mux.HandleFunc("POST /s/{token}/verify", g.verifySubmit)
		mux.HandleFunc("POST /s/{token}/otp", g.otpSubmit)
		mux.HandleFunc("POST /s/{token}/revoke-claim", g.revokeClaim)
	}
	if deps.AccessRequests != nil {
		mux.HandleFunc("GET /s/{token}/request-access", g.requestAccessPage)
		mux.HandleFunc("POST /s/{token}/request-access", g.requestAccessSubmit)
		mux.HandleFunc("GET /s/{token}/request-status", g.requestStatus)
	}
}

type gatewayRestrictedHandlers struct {
	deps GatewayDeps
	pub  *publicHandlers
}

// downloadOrVerify branches on access_mode. Public shares take the
// existing pub.serve path unchanged; restricted shares without a valid
// claim cookie are redirected to /s/{token}/verify (or 401 for JSON
// clients and HEAD probes).
func (g *gatewayRestrictedHandlers) downloadOrVerify(w http.ResponseWriter, r *http.Request, mode serveMode) {
	token := r.PathValue("token")
	share, err := g.deps.Public.Resolve(r.Context(), token)
	if err != nil || !share.IsRestricted() {
		g.pub.serve(w, r, token, mode)
		return
	}
	claim := readClaimCookie(r)
	payload, err := g.deps.Public.OpenWithClaim(r.Context(), token, claim)
	if err != nil {
		if errors.Is(err, app.ErrClaimRequired) {
			// Every GET that hits a restricted share and is turned
			// away is an access denial, and belongs in the durable
			// trail. Two reason codes distinguish the cases:
			//   - no cookie → reason=claim_required, recipient_id=""
			//   - cookie present → InspectClaim classifies why
			//     (claim_revoked / claim_expired / otp_required /
			//     claim_missing) and recovers recipient_id when
			//     possible.
			// HEAD stays silent (RFC 9110 § 9.3.2); an operator with a
			// real download attempt will see the GET row.
			if mode == serveDownload {
				g.recordRestrictedDenial(r, share.ID, claim)
			}
			if mode == serveProbe {
				w.Header().Set("WWW-Authenticate", "ShareClaim")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if wantsJSON(r) {
				writeError(w, http.StatusUnauthorized, "claim_required", "verification required")
				return
			}
			http.Redirect(w, r, "/s/"+token+"/verify", http.StatusSeeOther)
			return
		}
		// Any other error (share_not_available, share_exhausted, etc.)
		// flows back through the existing denial path so its audit +
		// share_access_event row still land. The claim cookie — if
		// present — resolves to a recipient_id so the denial is
		// durably attributable on the recipient activity timeline.
		rc := enrichment.Extract(r, g.deps.TrustedProxies)
		recipientID := g.deps.Public.LookupClaimRecipient(r.Context(), claim)
		_ = g.deps.Public.RecordAccess(r.Context(), share.ID, domain.AccessEvent{
			Succeeded:   false,
			RecipientID: recipientID,
			RemoteIP:    rc.RemoteIP,
			UserAgent:   rc.UserAgent,
			Referer:     rc.Referer,
			Metadata:    map[string]any{"reason": classifyShareError(err), "restricted": true, "request_id": rc.RequestID},
		})
		writeDomainError(w, err)
		return
	}
	defer payload.Body.Close()
	ct := payload.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if payload.OriginalName != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+payload.OriginalName+`"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if mode == serveProbe {
		return
	}
	n, copyErr := io.Copy(w, payload.Body)
	rc := enrichment.Extract(r, g.deps.TrustedProxies)
	// payload.RecipientID is populated by OpenWithClaim for restricted
	// shares. Every access row we write on this path — success,
	// denial, stream-interrupted — carries it so the recipient
	// timeline reflects the full delivery lifecycle.
	if copyErr != nil || (payload.Size > 0 && n < payload.Size) {
		_ = g.deps.Public.RecordAccess(r.Context(), payload.Share.ID, domain.AccessEvent{
			Succeeded:   false,
			RecipientID: payload.RecipientID,
			RemoteIP:    rc.RemoteIP,
			UserAgent:   rc.UserAgent,
			Referer:     rc.Referer,
			Metadata: map[string]any{
				"reason":        "stream_interrupted",
				"bytes_written": n,
				"restricted":    true,
				"request_id":    rc.RequestID,
			},
		})
		return
	}
	_, _ = g.deps.Public.CountDownload(r.Context(), payload.Share.ID)
	_ = g.deps.Public.RecordAccess(r.Context(), payload.Share.ID, domain.AccessEvent{
		Succeeded:   true,
		RecipientID: payload.RecipientID,
		RemoteIP:    rc.RemoteIP,
		UserAgent:   rc.UserAgent,
		Referer:     rc.Referer,
		Metadata: map[string]any{
			"bytes_written": n,
			"restricted":    true,
			"request_id":    rc.RequestID,
		},
	})
}

// recordRestrictedDenial writes the share_access_events row that
// represents every turned-away GET on a restricted share. Called from
// the ErrClaimRequired branch in downloadOrVerify. The row's reason
// field distinguishes the two operator-facing cases:
//
//   - No cookie was presented — reason="claim_required", recipient_id="".
//     The caller hasn't verified yet. Landing this in the access log
//     means the operator's /access view shows the full pattern of
//     turned-away attempts, not just the ones that already had a
//     cookie.
//   - Cookie present — InspectClaim classifies why it isn't redeemable
//     (claim_revoked, claim_expired, otp_required, claim_missing) and
//     recovers recipient_id where the cookie maps to a known row.
//     Recipient attribution lets the recipient-timeline view render
//     the denial alongside challenges and successful deliveries.
//
// In both cases the downstream Service.RecordAccess emits a
// shares.access_denied audit event with the same reason + recipient,
// so the audit trail and the recipient timeline stay consistent.
func (g *gatewayRestrictedHandlers) recordRestrictedDenial(r *http.Request, shareID, rawClaim string) {
	rc := enrichment.Extract(r, g.deps.TrustedProxies)
	recipientID := ""
	reason := domain.ReasonClaimRequired
	if rawClaim != "" {
		inspect := g.deps.Public.InspectClaim(r.Context(), rawClaim)
		recipientID = inspect.RecipientID
		if inspect.Reason != "" {
			reason = inspect.Reason
		} else {
			// Cookie was presented but lookup came back empty. This
			// race (cookie outlives its row) is rare but we still
			// want it visible as a denial, not swallowed.
			reason = domain.ReasonClaimMissing
		}
	}
	_ = g.deps.Public.RecordAccess(r.Context(), shareID, domain.AccessEvent{
		Succeeded:   false,
		RecipientID: recipientID,
		RemoteIP:    rc.RemoteIP,
		UserAgent:   rc.UserAgent,
		Referer:     rc.Referer,
		Metadata: map[string]any{
			"reason":     reason,
			"restricted": true,
			"request_id": rc.RequestID,
		},
	})
}

func (g *gatewayRestrictedHandlers) verifyPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = verifyPageTmpl.Execute(w, verifyPageData{Token: token, Mode: "passcode"})
}

func (g *gatewayRestrictedHandlers) verifySubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	email, passcode := readVerifyBody(r)
	if email == "" || passcode == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", "email and passcode are required")
		return
	}
	rctx := remoteCtxFrom(r, g.deps.Deps)
	res, err := g.deps.Verification.VerifyPasscode(r.Context(), token, email, passcode, rctx)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if res.OTPRequired {
		g.setClaimCookie(w, token, res.PendingClaimToken)
		if wantsJSON(r) {
			body := map[string]any{"otp_required": true}
			// RawOTP is populated only in dev mode (DevModeOTPEcho). In
			// production an OTPDispatcher delivers the code out-of-band
			// and this stays empty, so the field is omitted entirely
			// rather than returned blank.
			if res.RawOTP != "" {
				body["otp"] = res.RawOTP
			}
			writeJSON(w, http.StatusAccepted, body)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = verifyPageTmpl.Execute(w, verifyPageData{Token: token, Mode: "otp", OTP: res.RawOTP})
		return
	}
	g.setClaimCookie(w, token, res.RawClaimToken)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"verified": true})
		return
	}
	http.Redirect(w, r, "/s/"+token, http.StatusSeeOther)
}

func (g *gatewayRestrictedHandlers) otpSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	otp := readOTPBody(r)
	pending := readClaimCookie(r)
	if otp == "" || pending == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", "otp is required")
		return
	}
	rctx := remoteCtxFrom(r, g.deps.Deps)
	res, err := g.deps.Verification.SubmitOTP(r.Context(), token, pending, otp, rctx)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	g.setClaimCookie(w, token, res.RawClaimToken)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"verified": true})
		return
	}
	http.Redirect(w, r, "/s/"+token, http.StatusSeeOther)
}

func (g *gatewayRestrictedHandlers) revokeClaim(w http.ResponseWriter, r *http.Request) {
	g.clearClaimCookie(w, r.PathValue("token"))
	w.WriteHeader(http.StatusNoContent)
}

// requestAccessPage serves the HTML form a non-recipient uses to ask the owner
// for access. It exposes nothing about the share beyond what the token holder
// already implicitly knows.
func (g *gatewayRestrictedHandlers) requestAccessPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = verifyPageTmpl.Execute(w, verifyPageData{Token: token, Mode: "request"})
}

// requestAccessSubmit records a pending access request. It returns only a
// coarse status — never file metadata, internal ids, owner data, or secrets.
func (g *gatewayRestrictedHandlers) requestAccessSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	email, message := readRequestAccessBody(r)
	if email == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", "email is required")
		return
	}
	rctx := remoteCtxFrom(r, g.deps.Deps)
	res, err := g.deps.AccessRequests.SubmitAccessRequest(r.Context(), token, email, message, rctx)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusAccepted, PublicAccessRequestResponse{Status: res.Status})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = verifyPageTmpl.Execute(w, verifyPageData{Token: token, Mode: "requested", Status: res.Status})
}

// requestStatus returns the coarse status for the email supplied as a query
// param. Deliberately minimal to bound the enumeration value of the endpoint:
// a caller already holds the share token (a capability) and is told only
// none/pending/approved/denied for the email they name — never decision
// metadata, recipient details, or the passcode.
func (g *gatewayRestrictedHandlers) requestStatus(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email query parameter is required")
		return
	}
	res, err := g.deps.AccessRequests.AccessRequestStatus(r.Context(), token, email)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, PublicAccessRequestResponse{Status: res.Status})
}

func readRequestAccessBody(r *http.Request) (email, message string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Email   string `json:"email"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		return strings.TrimSpace(body.Email), strings.TrimSpace(body.Message)
	}
	_ = r.ParseForm()
	return strings.TrimSpace(r.FormValue("email")), strings.TrimSpace(r.FormValue("message"))
}

func readClaimCookie(r *http.Request) string {
	c, err := r.Cookie(ShareClaimCookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

func (g *gatewayRestrictedHandlers) setClaimCookie(w http.ResponseWriter, token, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ShareClaimCookieName,
		Value:    raw,
		Path:     "/s/" + token,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   g.deps.SecureCookies,
	})
}

// clearClaimCookie expires the claim cookie. The attributes (Path,
// HttpOnly, SameSite, Secure) mirror setClaimCookie so browsers reliably
// match and remove the existing cookie rather than leaving a stale copy.
func (g *gatewayRestrictedHandlers) clearClaimCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ShareClaimCookieName,
		Value:    "",
		Path:     "/s/" + token,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   g.deps.SecureCookies,
		MaxAge:   -1,
	})
}

func readVerifyBody(r *http.Request) (email, passcode string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Email    string `json:"email"`
			Passcode string `json:"passcode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		return strings.TrimSpace(body.Email), strings.TrimSpace(body.Passcode)
	}
	_ = r.ParseForm()
	return strings.TrimSpace(r.FormValue("email")), strings.TrimSpace(r.FormValue("passcode"))
}

func readOTPBody(r *http.Request) string {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			OTP string `json:"otp"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		return strings.TrimSpace(body.OTP)
	}
	_ = r.ParseForm()
	return strings.TrimSpace(r.FormValue("otp"))
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// remoteCtxFrom builds the enriched RemoteContext the service uses to
// tag share_challenges rows and audit events. Risk + country enrichment
// goes through the same pluggable path as share_access_events so the
// recipient timeline lines up with the public-access timeline on the
// audit UI. deps.RiskScorer / deps.CountryLookup fall back to the
// Heuristic + DefaultCountryLookup defaults when not configured.
func remoteCtxFrom(r *http.Request, deps api_Deps) app.RemoteContext {
	rc := enrichment.Extract(r, deps.TrustedProxies)
	scorer := deps.RiskScorer
	if scorer == nil {
		scorer = enrichment.HeuristicRiskScorer{}
	}
	country := deps.CountryLookup
	if country == nil {
		country = enrichment.DefaultCountryLookup{}
	}
	score, _ := scorer.Score(map[string]string{
		"remote_ip":  rc.RemoteIP,
		"user_agent": rc.UserAgent,
		// Verification paths can't know whether the IP is new for this
		// subject yet, so we flag false; the scorer's other heuristics
		// still fire on suspicious UAs / missing headers.
		"new_ip_for_subject": "false",
		"near_download_cap":  "false",
	})
	return app.RemoteContext{
		RemoteIP:    rc.RemoteIP,
		UserAgent:   rc.UserAgent,
		Referer:     rc.Referer,
		CountryCode: country.Lookup(rc.RemoteIP),
		RiskScore:   score,
	}
}

// api_Deps aliases Deps so the helper above can be called from both the
// authenticated handler layer (unused) and the gateway handlers without
// importing this package's own Deps twice under different names.
type api_Deps = Deps

// verifyPageTmpl renders the minimal HTML passcode/OTP form. Intentionally
// self-contained — the gateway should not depend on the SPA bundle.
type verifyPageData struct {
	Token  string
	Mode   string // "passcode" | "otp" | "request" | "requested"
	OTP    string // dev-time surfacing only
	Err    string
	Status string // coarse access-request status on the "requested" page
}

var verifyPageTmpl = template.Must(template.New("verify").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify to download</title>
<style>
body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:1rem;color:#222}
h1{font-size:1.25rem}
label{display:block;margin-top:0.75rem}
input{width:100%;padding:0.5rem;font-size:1rem;border:1px solid #888;border-radius:4px;box-sizing:border-box}
button{margin-top:1rem;padding:0.6rem 1.2rem;font-size:1rem;border-radius:4px;border:0;background:#1d4ed8;color:#fff}
.note{margin-top:1rem;color:#555;font-size:0.9rem}
.code{font-family:ui-monospace,monospace;background:#eef;padding:0.2rem 0.4rem;border-radius:3px}
</style></head>
<body>
{{if eq .Mode "passcode"}}
<h1>This share requires verification</h1>
<form method="POST" action="/s/{{.Token}}/verify">
  <label>Email<input name="email" type="email" autocomplete="email" required></label>
  <label>Passcode<input name="passcode" type="text" autocomplete="one-time-code" required></label>
  <button type="submit">Verify</button>
</form>
<p class="note">Enter the passcode provided by the share owner. Your download starts after verification.</p>
<p class="note">Not on the list? <a href="/s/{{.Token}}/request-access">Request access</a>.</p>
{{else if eq .Mode "request"}}
<h1>Request access to this share</h1>
<form method="POST" action="/s/{{.Token}}/request-access">
  <label>Email<input name="email" type="email" autocomplete="email" required></label>
  <label>Message (optional)<input name="message" type="text"></label>
  <button type="submit">Request access</button>
</form>
<p class="note">The share owner will review your request. If approved, ask them for your passcode, then return here to verify and download.</p>
{{else if eq .Mode "requested"}}
<h1>Access request received</h1>
<p class="note">Your request status is <span class="code">{{.Status}}</span>. If approved, use the passcode provided by the share owner to <a href="/s/{{.Token}}/verify">verify and download</a>.</p>
{{else}}
<h1>This share requires verification</h1>
<form method="POST" action="/s/{{.Token}}/otp">
  <label>One-time code<input name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" required></label>
  <button type="submit">Submit OTP</button>
</form>
{{if .OTP}}<p class="note">Local verification code: <span class="code">{{.OTP}}</span></p>{{end}}
{{end}}
{{if .Err}}<p class="note" style="color:#b91c1c">{{.Err}}</p>{{end}}
</body></html>`))
