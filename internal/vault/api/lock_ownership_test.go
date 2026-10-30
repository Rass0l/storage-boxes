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

// A user who did NOT create an unlock session must not be able to lock it.
// Anyone authed could issue `DELETE /boxes/{id}/sessions/{sess}` against a
// guessed or leaked unlock-session ID; the service layer must refuse.
func TestLockRefusesForeignUnlockSession(t *testing.T) {
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
	alice, _ := idSvc.CreateUser(context.Background(), identityapp.CreateUserInput{Email: "a@ex.com", Password: "password1"})
	bob, _ := idSvc.CreateUser(context.Background(), identityapp.CreateUserInput{Email: "b@ex.com", Password: "password2"})

	mux := http.NewServeMux()
	identityapi.RegisterRoutes(mux, identityapi.Deps{Service: idSvc})
	RegisterRoutes(mux, Deps{Vault: vaultSvc, Identity: idSvc})

	// Alice creates a box and unlocks it directly via service.
	box, _ := vaultSvc.CreateBoxFull(context.Background(), vaultapp.CreateBoxFullInput{
		OwnerUserID: alice.ID, Name: "a-box", SizeBytes: 1024, Password: "boxpass1",
	})
	unlock, _ := vaultSvc.UnlockBox(context.Background(), box.ID, alice.ID, "boxpass1")

	// Bob logs in via HTTP.
	body, _ := json.Marshal(map[string]string{"email": "b@ex.com", "password": "password2"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("bob login: %d", rr.Code)
	}
	var bobCk *http.Cookie
	var bobCSRF string
	for _, c := range rr.Result().Cookies() {
		switch c.Name {
		case identityapi.SessionCookieName:
			bobCk = c
		case identityapi.CSRFCookieName:
			bobCSRF = c.Value
		}
	}

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/sessions/"+unlock.ID, nil)
	req.AddCookie(bobCk)
	req.AddCookie(&http.Cookie{Name: identityapi.CSRFCookieName, Value: bobCSRF})
	req.Header.Set(identityapi.CSRFHeaderName, bobCSRF)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when bob tries to lock alice's session, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Alice's unlock session must still be resolvable after bob's failed attempt.
	if _, err := vaultSvc.ResolveUnlock(context.Background(), unlock.ID); err != nil {
		t.Fatalf("alice's unlock session corrupted after foreign lock attempt: %v", err)
	}
	_ = bob
}
