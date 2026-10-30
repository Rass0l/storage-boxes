package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityapi "github.com/Rass0l/storage-boxes/internal/identity/api"
	identityapp "github.com/Rass0l/storage-boxes/internal/identity/app"
	identityinfra "github.com/Rass0l/storage-boxes/internal/identity/infra"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestBoxOwnershipIsolationHTTP boots one mux with two users and verifies
// that user B cannot list, delete, or unlock user A's box via the HTTP API.
func TestBoxOwnershipIsolationHTTP(t *testing.T) {
	users := identityinfra.NewMemoryUserStore()
	creds := identityinfra.NewMemoryCredentialStore()
	roles := identityinfra.NewMemoryRoleStore()
	sessions := identityinfra.NewMemorySessionStore(identityinfra.SessionOptions{
		IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour,
	})
	idSvc := identityapp.NewService(identityapp.Deps{
		Users: users, Credentials: creds, Sessions: sessions, Roles: roles,
		Hasher: fastHasher{}, IDs: ids.RandomGenerator{}, Clock: clock.RealClock{},
	})
	vaultSvc := vaultapp.NewService(vaultapp.ServiceDeps{
		Boxes:   vaultinfra.NewMemoryBoxRepository(),
		Crypto:  vaultinfra.NewMemoryCryptoStore(),
		Files:   vaultinfra.NewMemoryFileCatalog(),
		Unlocks: vaultinfra.NewMemoryUnlockSessionStore(),
		Engine:  vaultinfra.NewEncryptedFSBoxEngine(t.TempDir()),
		IDs:     ids.RandomGenerator{}, Clock: clock.RealClock{},
	})
	// Seed two users directly.
	if _, err := idSvc.CreateUser(context.Background(), identityapp.CreateUserInput{
		Email: "alice@example.com", Password: "password1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := idSvc.CreateUser(context.Background(), identityapp.CreateUserInput{
		Email: "bob@example.com", Password: "password2",
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	identityapi.RegisterRoutes(mux, identityapi.Deps{Service: idSvc})
	RegisterRoutes(mux, Deps{Vault: vaultSvc, Identity: idSvc})

	login := func(email, pass string) (*http.Cookie, string) {
		body, _ := json.Marshal(map[string]string{"email": email, "password": pass})
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("login %s: %d %s", email, rr.Code, rr.Body.String())
		}
		var sess *http.Cookie
		var csrf string
		for _, c := range rr.Result().Cookies() {
			if c.Name == identityapi.SessionCookieName {
				sess = c
			}
			if c.Name == identityapi.CSRFCookieName {
				csrf = c.Value
			}
		}
		return sess, csrf
	}

	aliceSession, aliceCSRF := login("alice@example.com", "password1")
	bobSession, bobCSRF := login("bob@example.com", "password2")

	do := func(method, path string, body any, session *http.Cookie, csrf string) *httptest.ResponseRecorder {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(session)
		req.AddCookie(&http.Cookie{Name: identityapi.CSRFCookieName, Value: csrf})
		if method != http.MethodGet {
			req.Header.Set(identityapi.CSRFHeaderName, csrf)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	// Alice creates a box.
	rr := do(http.MethodPost, "/api/v1/boxes",
		CreateBoxRequest{Name: "alice-secret", SizeBytes: 1024, Password: "boxpass1"},
		aliceSession, aliceCSRF)
	if rr.Code != http.StatusCreated {
		t.Fatalf("alice create: %d %s", rr.Code, rr.Body.String())
	}
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	// Bob should not see it when listing.
	rr = do(http.MethodGet, "/api/v1/boxes", nil, bobSession, bobCSRF)
	if rr.Code != http.StatusOK {
		t.Fatalf("bob list: %d", rr.Code)
	}
	var list BoxListResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("bob should see 0 boxes, got %d", len(list.Items))
	}

	// Bob cannot unlock it even with the right password.
	rr = do(http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		UnlockBoxRequest{Password: "boxpass1"}, bobSession, bobCSRF)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("bob unlock should 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// Bob cannot delete it.
	rr = do(http.MethodDelete, "/api/v1/boxes/"+box.ID, nil, bobSession, bobCSRF)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("bob delete should 403, got %d: %s", rr.Code, rr.Body.String())
	}
}
