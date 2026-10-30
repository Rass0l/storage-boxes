package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
	"github.com/Rass0l/storage-boxes/internal/identity/infra"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
)

type fastHasher struct{}

func (fastHasher) Hash(p string) (string, error)          { return "hashed:" + p, nil }
func (fastHasher) Verify(p, encoded string) (bool, error) { return encoded == "hashed:"+p, nil }

func newTestService(t *testing.T) *app.Service {
	t.Helper()
	users := infra.NewMemoryUserStore()
	creds := infra.NewMemoryCredentialStore()
	roles := infra.NewMemoryRoleStore()
	sessions := infra.NewMemorySessionStore(infra.SessionOptions{
		IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour,
	})
	return app.NewService(app.Deps{
		Users: users, Credentials: creds, Sessions: sessions, Roles: roles,
		Hasher: fastHasher{}, IDs: ids.RandomGenerator{}, Clock: clock.RealClock{},
	})
}

func loginAndGetSession(t *testing.T, mux *http.ServeMux, email, password string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(LoginRequest{Email: email, Password: password})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c
		}
	}
	t.Fatal("expected session cookie")
	return nil
}

func TestMeUnauthenticated(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: newTestService(t)})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.CreateUser(context.Background(), app.CreateUserInput{
		Email: "u@example.com", Password: "password1", DisplayName: "U",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc})

	session := loginAndGetSession(t, mux, "u@example.com", "password1")

	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq.AddCookie(session)
	meRR := httptest.NewRecorder()
	mux.ServeHTTP(meRR, meReq)
	if meRR.Code != http.StatusOK {
		t.Fatalf("me: expected 200, got %d", meRR.Code)
	}

	loReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	loReq.AddCookie(session)
	loRR := httptest.NewRecorder()
	mux.ServeHTTP(loRR, loReq)
	if loRR.Code != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d", loRR.Code)
	}

	me2Req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	me2Req.AddCookie(session)
	me2 := httptest.NewRecorder()
	mux.ServeHTTP(me2, me2Req)
	if me2.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout me: expected 401, got %d", me2.Code)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	svc := newTestService(t)
	_, _ = svc.CreateUser(context.Background(), app.CreateUserInput{Email: "u@example.com", Password: "password1"})
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc})
	body, _ := json.Marshal(LoginRequest{Email: "u@example.com", Password: "bad"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestListUsersRequiresAdmin(t *testing.T) {
	svc := newTestService(t)
	_, _ = svc.CreateUser(context.Background(), app.CreateUserInput{Email: "u@example.com", Password: "password1"})
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc})
	session := loginAndGetSession(t, mux, "u@example.com", "password1")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}
