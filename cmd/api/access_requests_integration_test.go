package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auditdomain "github.com/Rass0l/storage-boxes/internal/audit/domain"
	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	sharesapi "github.com/Rass0l/storage-boxes/internal/shares/api"
)

// arTestCtx bundles a logged-in admin client, a created restricted share, and
// a public gateway mux wired with the access-request endpoints.
type arTestCtx struct {
	c       *client
	app     *App
	pmux    *http.ServeMux
	shareID string
	token   string
}

func setupRestrictedShareWithRequests(t *testing.T) *arTestCtx {
	t.Helper()
	t.Setenv("SHARE_STAGE_ROOT", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "aa"+repeat("bb", 31))
	app := buildTestApp(t)
	c := &client{t: t, handler: app.Handler}

	rr := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "admin@example.local", "password": "admin-dev-password-change-me"},
		"", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d", rr.Code)
	}
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case identityapi.SessionCookieName:
			c.session = ck
		case identityapi.CSRFCookieName:
			c.csrf = ck.Value
		}
	}
	rr = c.do(http.MethodPost, "/api/v1/boxes", map[string]any{
		"name": "ar-box", "size_bytes": 1024, "password": "boxpass1",
	}, "", nil, "")
	var box struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = c.do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		map[string]string{"password": "boxpass1"}, "", nil, "")
	var unlocked struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	rr = c.do(http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/r.txt",
		nil, unlocked.SessionID, []byte("approved-payload"), "text/plain")
	var upload struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &upload)

	rr = c.do(http.MethodPost, "/api/v1/shares", map[string]any{
		"box_id":           box.ID,
		"file_entry_id":    upload.Entry.ID,
		"expiry_seconds":   3600,
		"max_downloads":    5,
		"access_mode":      "restricted",
		"recipient_emails": []string{"member@example.com"},
	}, unlocked.SessionID, nil, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create restricted share: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID         string `json:"id"`
		Token      string `json:"token"`
		Recipients []struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			Passcode string `json:"passcode"`
		} `json:"recipients"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	svc := app.publicShareSvc()
	pmux := http.NewServeMux()
	sharesapi.RegisterGatewayRoutes(pmux, sharesapi.GatewayDeps{
		Deps:           sharesapi.Deps{Public: svc, Service: svc},
		Verification:   svc,
		AccessRequests: svc,
	})
	return &arTestCtx{c: c, app: app, pmux: pmux, shareID: created.ID, token: created.Token}
}

// TestAccessRequestFullLifecycle drives the whole flow end-to-end:
// non-recipient requests → owner sees pending → denied delivery before
// approval → approve → verify with minted passcode → download → audit trail.
func TestAccessRequestFullLifecycle(t *testing.T) {
	tc := setupRestrictedShareWithRequests(t)

	// A non-recipient submits an access request via the public gateway.
	submit := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/request-access",
		map[string]string{"email": "guest@example.com", "message": "please"})
	if submit.Code != http.StatusAccepted {
		t.Fatalf("request-access: %d %s", submit.Code, submit.Body.String())
	}
	var submitBody map[string]any
	_ = json.Unmarshal(submit.Body.Bytes(), &submitBody)
	if submitBody["status"] != "pending" {
		t.Fatalf("want pending status, got %v", submitBody["status"])
	}
	// The public response must not leak anything beyond status.
	if len(submitBody) != 1 {
		t.Fatalf("public submit leaked fields: %v", submitBody)
	}

	// Denied delivery BEFORE approval: a guest with no claim is turned away.
	resp := callPublic(t, tc.pmux, "GET", "/s/"+tc.token)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("pre-approval download should redirect to verify, got %d", resp.Code)
	}

	// Owner lists pending requests.
	rr := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests?status=pending", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list access-requests: %d %s", rr.Code, rr.Body.String())
	}
	var list struct {
		Items []struct {
			ID             string `json:"id"`
			RequesterEmail string `json:"requester_email"`
			Status         string `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].RequesterEmail != "guest@example.com" {
		t.Fatalf("expected one pending request for guest, got %+v", list.Items)
	}
	reqID := list.Items[0].ID

	// Owner approves; passcode is returned exactly once.
	rr = tc.c.do(http.MethodPost, "/api/v1/shares/"+tc.shareID+"/access-requests/"+reqID+"/approve",
		map[string]any{}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	var approve struct {
		Request struct {
			Status string `json:"status"`
		} `json:"request"`
		Recipient struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"recipient"`
		Passcode    string `json:"passcode"`
		Reactivated bool   `json:"reactivated"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &approve)
	if approve.Request.Status != "approved" || approve.Passcode == "" || approve.Reactivated {
		t.Fatalf("unexpected approve result: %+v", approve)
	}

	// The approved requester must STILL verify normally — approval is not a
	// shortcut. Verify with the minted passcode, then download.
	verify := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/verify",
		map[string]string{"email": "guest@example.com", "passcode": approve.Passcode})
	if verify.Code != http.StatusOK {
		t.Fatalf("verify after approval: %d %s", verify.Code, verify.Body.String())
	}
	var claimCookie *http.Cookie
	for _, ck := range verify.Result().Cookies() {
		if ck.Name == sharesapi.ShareClaimCookieName {
			claimCookie = ck
		}
	}
	if claimCookie == nil {
		t.Fatal("verify did not set claim cookie")
	}
	req := httptest.NewRequest("GET", "/s/"+tc.token, nil)
	req.AddCookie(claimCookie)
	dl := httptest.NewRecorder()
	tc.pmux.ServeHTTP(dl, req)
	if dl.Code != http.StatusOK || !bytes.Equal(dl.Body.Bytes(), []byte("approved-payload")) {
		t.Fatalf("download after approval+verify failed: %d %q", dl.Code, dl.Body.String())
	}

	// Audit trail: request, approval, recipient add, verification, delivery.
	assertAuditHas(t, tc.c, map[string]bool{
		auditdomain.EventShareAccessRequested:       false,
		auditdomain.EventShareAccessRequestApproved: false,
		auditdomain.EventShareRecipientAdded:        false,
		auditdomain.EventShareChallengeSucceeded:    false,
		auditdomain.EventShareAccessed:              false,
	})
}

// TestAccessRequestApprovedThenRevokedReflectsEverywhere proves "approved" is
// not treated as permanent truth: after the approval's recipient is revoked,
// the PUBLIC status stops saying approved and the OWNER list shows the
// approved request with recipient_state=revoked — while the request's
// historical status stays "approved".
func TestAccessRequestApprovedThenRevokedReflectsEverywhere(t *testing.T) {
	tc := setupRestrictedShareWithRequests(t)
	// Submit + approve.
	if rr := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/request-access",
		map[string]string{"email": "guest@example.com"}); rr.Code != http.StatusAccepted {
		t.Fatalf("request-access: %d", rr.Code)
	}
	rr := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests?status=pending", nil, "", nil, "")
	var pend struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &pend)
	rr = tc.c.do(http.MethodPost, "/api/v1/shares/"+tc.shareID+"/access-requests/"+pend.Items[0].ID+"/approve", map[string]any{}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	var approve struct {
		Recipient struct {
			ID string `json:"id"`
		} `json:"recipient"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &approve)

	statusOf := func(email string) string {
		resp := callPublic(t, tc.pmux, "GET", "/s/"+tc.token+"/request-status?email="+email)
		if resp.Code != http.StatusOK {
			t.Fatalf("request-status: %d", resp.Code)
		}
		var b struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(resp.Body.Bytes(), &b)
		return b.Status
	}
	ownerRowState := func() (status, recipientState string) {
		r := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests", nil, "", nil, "")
		var l struct {
			Items []struct {
				Status         string `json:"status"`
				RecipientState string `json:"recipient_state"`
			} `json:"items"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &l)
		if len(l.Items) != 1 {
			t.Fatalf("want 1 request, got %d", len(l.Items))
		}
		return l.Items[0].Status, l.Items[0].RecipientState
	}

	// While the recipient is active: public approved, owner approved/active.
	if s := statusOf("guest@example.com"); s != "approved" {
		t.Fatalf("public status while active: want approved, got %q", s)
	}
	if st, rs := ownerRowState(); st != "approved" || rs != "active" {
		t.Fatalf("owner row while active: want approved/active, got %s/%s", st, rs)
	}

	// Owner revokes the recipient.
	if rr := tc.c.do(http.MethodDelete, "/api/v1/shares/"+tc.shareID+"/recipients/"+approve.Recipient.ID, nil, "", nil, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke recipient: %d", rr.Code)
	}

	// Public must NOT still say approved; owner row stays approved (history)
	// but is annotated recipient_state=revoked.
	if s := statusOf("guest@example.com"); s != "none" {
		t.Fatalf("public status after revoke: want none, got %q", s)
	}
	if st, rs := ownerRowState(); st != "approved" || rs != "revoked" {
		t.Fatalf("owner row after revoke: want approved/revoked, got %s/%s", st, rs)
	}
}

// TestAccessRequestDenyKeepsDeliveryBlocked proves a denied requester can't
// verify or download.
func TestAccessRequestDenyKeepsDeliveryBlocked(t *testing.T) {
	tc := setupRestrictedShareWithRequests(t)
	submit := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/request-access",
		map[string]string{"email": "nope@example.com"})
	if submit.Code != http.StatusAccepted {
		t.Fatalf("request-access: %d", submit.Code)
	}
	rr := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests?status=pending", nil, "", nil, "")
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	reqID := list.Items[0].ID

	rr = tc.c.do(http.MethodPost, "/api/v1/shares/"+tc.shareID+"/access-requests/"+reqID+"/deny",
		map[string]string{"reason": "not recognized"}, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("deny: %d %s", rr.Code, rr.Body.String())
	}
	// A denied requester is not a recipient — verification fails.
	verify := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/verify",
		map[string]string{"email": "nope@example.com", "passcode": "ANYTHING"})
	if verify.Code == http.StatusOK {
		t.Fatal("denied requester must not verify")
	}
	assertAuditHas(t, tc.c, map[string]bool{auditdomain.EventShareAccessRequestDenied: false})
}

// TestAccessRequestApproveReactivatesRevokedRecipient proves approving an
// access request from a previously-revoked recipient reactivates them.
func TestAccessRequestApproveReactivatesRevokedRecipient(t *testing.T) {
	tc := setupRestrictedShareWithRequests(t)
	// Revoke the preconfigured "member@example.com" recipient.
	rr := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/recipients", nil, "", nil, "")
	var recs struct {
		Items []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &recs)
	var memberID string
	for _, r := range recs.Items {
		if r.Email == "member@example.com" {
			memberID = r.ID
		}
	}
	if memberID == "" {
		t.Fatal("preconfigured recipient not found")
	}
	rr = tc.c.do(http.MethodDelete, "/api/v1/shares/"+tc.shareID+"/recipients/"+memberID, nil, "", nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke recipient: %d", rr.Code)
	}

	// The revoked member requests access again.
	submit := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/request-access",
		map[string]string{"email": "member@example.com"})
	if submit.Code != http.StatusAccepted {
		t.Fatalf("request-access: %d %s", submit.Code, submit.Body.String())
	}
	rr = tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests?status=pending", nil, "", nil, "")
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("want 1 pending, got %d", len(list.Items))
	}
	rr = tc.c.do(http.MethodPost, "/api/v1/shares/"+tc.shareID+"/access-requests/"+list.Items[0].ID+"/approve",
		map[string]any{}, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	var approve struct {
		Recipient struct {
			ID string `json:"id"`
		} `json:"recipient"`
		Passcode    string `json:"passcode"`
		Reactivated bool   `json:"reactivated"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &approve)
	if !approve.Reactivated {
		t.Fatal("approving a revoked recipient must set reactivated=true")
	}
	if approve.Recipient.ID != memberID {
		t.Fatalf("reactivation should reuse the recipient row %s, got %s", memberID, approve.Recipient.ID)
	}
	if approve.Passcode == "" {
		t.Fatal("reactivation must mint a fresh passcode")
	}
	assertAuditHas(t, tc.c, map[string]bool{auditdomain.EventShareRecipientReactivated: false})
}

// TestAccessRequestWorkerCleanupExpires drives the in-process cleanup job to
// expire a pending request whose TTL has passed.
func TestAccessRequestWorkerCleanupExpires(t *testing.T) {
	tc := setupRestrictedShareWithRequests(t)
	submit := publicJSON(t, tc.pmux, "POST", "/s/"+tc.token+"/request-access",
		map[string]string{"email": "stale@example.com"})
	if submit.Code != http.StatusAccepted {
		t.Fatalf("request-access: %d", submit.Code)
	}
	// Run cleanup well into the future so the request's TTL has elapsed.
	future := time.Now().UTC().Add(8 * 24 * time.Hour)
	n, err := tc.app.testAccessReqCleanup.Run(context.Background(), future, 100)
	if err != nil {
		t.Fatalf("cleanup run: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 cleaned, got %d", n)
	}
	rr := tc.c.do(http.MethodGet, "/api/v1/shares/"+tc.shareID+"/access-requests?status=expired", nil, "", nil, "")
	var list struct {
		Items []struct {
			DecisionReason string `json:"decision_reason"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].DecisionReason != "expired_ttl" {
		t.Fatalf("expected one expired(ttl) request, got %+v", list.Items)
	}
}

// assertAuditHas fetches the audit log and asserts every event type in want
// appears. The map values are ignored on input (callers pass false).
func assertAuditHas(t *testing.T, c *client, want map[string]bool) {
	t.Helper()
	rr := c.do(http.MethodGet, "/api/v1/audit/events?limit=200", nil, "", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list: %d", rr.Code)
	}
	var events struct {
		Items []struct {
			EventType string `json:"event_type"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &events)
	for _, e := range events.Items {
		if _, ok := want[e.EventType]; ok {
			want[e.EventType] = true
		}
	}
	for et, seen := range want {
		if !seen {
			t.Errorf("missing expected audit event %q", et)
		}
	}
}
