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

type fastHasher struct{}

func (fastHasher) Hash(p string) (string, error)          { return "hashed:" + p, nil }
func (fastHasher) Verify(p, encoded string) (bool, error) { return encoded == "hashed:"+p, nil }

type testHarness struct {
	mux       *http.ServeMux
	identity  *identityapp.Service
	vault     *vaultapp.Service
	sessionCk *http.Cookie
	csrfToken string
	userID    string
}

func newHarness(t *testing.T, email, password string) *testHarness {
	t.Helper()
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
	boxes := vaultinfra.NewMemoryBoxRepository()
	cryptoStore := vaultinfra.NewMemoryCryptoStore()
	files := vaultinfra.NewMemoryFileCatalog()
	unlocks := vaultinfra.NewMemoryUnlockSessionStore()
	vaultSvc := vaultapp.NewService(vaultapp.ServiceDeps{
		Boxes: boxes, Crypto: cryptoStore, Files: files,
		Unlocks: unlocks, Engine: vaultinfra.NewEncryptedFSBoxEngine(t.TempDir()),
		IDs: ids.RandomGenerator{}, Clock: clock.RealClock{},
	})
	user, err := idSvc.CreateUser(context.Background(), identityapp.CreateUserInput{
		Email: email, Password: password,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	mux := http.NewServeMux()
	identityapi.RegisterRoutes(mux, identityapi.Deps{Service: idSvc})
	RegisterRoutes(mux, Deps{Vault: vaultSvc, Identity: idSvc})

	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	h := &testHarness{mux: mux, identity: idSvc, vault: vaultSvc, userID: user.ID}
	for _, c := range rr.Result().Cookies() {
		switch c.Name {
		case identityapi.SessionCookieName:
			h.sessionCk = c
		case identityapi.CSRFCookieName:
			h.csrfToken = c.Value
		}
	}
	if h.sessionCk == nil || h.csrfToken == "" {
		t.Fatal("expected session + csrf cookies")
	}
	return h
}

func (h *testHarness) doRaw(t *testing.T, method, path string, raw []byte, contentType, unlockSess string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.AddCookie(h.sessionCk)
	req.AddCookie(&http.Cookie{Name: identityapi.CSRFCookieName, Value: h.csrfToken})
	if method != http.MethodGet {
		req.Header.Set(identityapi.CSRFHeaderName, h.csrfToken)
	}
	if unlockSess != "" {
		req.Header.Set(UnlockHeaderName, unlockSess)
	}
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)
	return rr
}

func (h *testHarness) do(t *testing.T, method, path string, body any, unlockSess string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.AddCookie(h.sessionCk)
	req.AddCookie(&http.Cookie{Name: identityapi.CSRFCookieName, Value: h.csrfToken})
	if method != http.MethodGet {
		req.Header.Set(identityapi.CSRFHeaderName, h.csrfToken)
	}
	if unlockSess != "" {
		req.Header.Set(UnlockHeaderName, unlockSess)
	}
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)
	return rr
}

func TestCreateAndListBox(t *testing.T) {
	h := newHarness(t, "u@example.com", "password1")
	rr := h.do(t, http.MethodPost, "/api/v1/boxes", CreateBoxRequest{
		Name: "my-box", SizeBytes: 1024, Password: "boxpass1",
	}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	if box.ID == "" {
		t.Fatal("expected box id")
	}

	rr = h.do(t, http.MethodGet, "/api/v1/boxes", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var list BoxListResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].ID != box.ID {
		t.Fatalf("expected one box, got %+v", list)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	h := newHarness(t, "u@example.com", "password1")
	rr := h.do(t, http.MethodPost, "/api/v1/boxes", CreateBoxRequest{
		Name: "b", SizeBytes: 1024, Password: "boxpass1",
	}, "")
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		UnlockBoxRequest{Password: "wrong"}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUnlockCorrectPasswordAndLock(t *testing.T) {
	h := newHarness(t, "u@example.com", "password1")
	rr := h.do(t, http.MethodPost, "/api/v1/boxes", CreateBoxRequest{
		Name: "b", SizeBytes: 1024, Password: "boxpass1",
	}, "")
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		UnlockBoxRequest{Password: "boxpass1"}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", rr.Code, rr.Body.String())
	}
	var unlocked UnlockResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &unlocked)
	if unlocked.SessionID == "" {
		t.Fatal("expected unlock session id")
	}

	rr = h.do(t, http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil, unlocked.SessionID)
	if rr.Code != http.StatusOK {
		t.Fatalf("list files: %d %s", rr.Code, rr.Body.String())
	}

	rr = h.do(t, http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil, "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without unlock, got %d", rr.Code)
	}

	rr = h.do(t, http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/sessions/"+unlocked.SessionID, nil, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("lock: %d %s", rr.Code, rr.Body.String())
	}
	rr = h.do(t, http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil, unlocked.SessionID)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected auth/forbidden after lock, got 200")
	}
}

func TestFileOpsRoundTrip(t *testing.T) {
	h := newHarness(t, "u@example.com", "password1")
	rr := h.do(t, http.MethodPost, "/api/v1/boxes",
		CreateBoxRequest{Name: "b", SizeBytes: 1024, Password: "boxpass1"}, "")
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		UnlockBoxRequest{Password: "boxpass1"}, "")
	var un UnlockResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &un)

	// Upload a file.
	content := []byte("hello vault world")
	rr = h.doRaw(t, http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/greetings.txt",
		content, "text/plain", un.SessionID)
	if rr.Code != http.StatusCreated {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	var resp FileResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Entry.ID == "" || resp.Entry.LogicalPath != "/greetings.txt" {
		t.Fatalf("unexpected entry: %+v", resp.Entry)
	}

	// List.
	rr = h.do(t, http.MethodGet, "/api/v1/boxes/"+box.ID+"/files", nil, un.SessionID)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var list FileTreeResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list.Items))
	}

	// Read content.
	rr = h.do(t, http.MethodGet,
		"/api/v1/boxes/"+box.ID+"/files/"+resp.Entry.ID+"/content", nil, un.SessionID)
	if rr.Code != http.StatusOK {
		t.Fatalf("read: %d", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Fatalf("content mismatch: %q", rr.Body.String())
	}

	// Create a folder.
	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/folders",
		CreateFolderRequest{LogicalPath: "/work"}, un.SessionID)
	if rr.Code != http.StatusCreated {
		t.Fatalf("folder: %d %s", rr.Code, rr.Body.String())
	}

	// Move the file into the folder.
	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/files/move",
		MoveFileRequest{FromPath: "/greetings.txt", ToPath: "/work/greetings.txt"}, un.SessionID)
	if rr.Code != http.StatusOK {
		t.Fatalf("move: %d %s", rr.Code, rr.Body.String())
	}

	// Delete it.
	rr = h.doRaw(t, http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/files?path=/work/greetings.txt", nil, "", un.SessionID)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}

	// Folder is now empty and can be deleted.
	rr = h.doRaw(t, http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/files?path=/work", nil, "", un.SessionID)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete folder: %d %s", rr.Code, rr.Body.String())
	}
}

func TestFolderNotEmptyConflict(t *testing.T) {
	h := newHarness(t, "u@example.com", "password1")
	rr := h.do(t, http.MethodPost, "/api/v1/boxes",
		CreateBoxRequest{Name: "b", SizeBytes: 1024, Password: "boxpass1"}, "")
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)
	rr = h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/sessions",
		UnlockBoxRequest{Password: "boxpass1"}, "")
	var un UnlockResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &un)

	h.do(t, http.MethodPost, "/api/v1/boxes/"+box.ID+"/folders",
		CreateFolderRequest{LogicalPath: "/work"}, un.SessionID)
	h.doRaw(t, http.MethodPut, "/api/v1/boxes/"+box.ID+"/files?path=/work/child.txt",
		[]byte("x"), "text/plain", un.SessionID)

	rr = h.doRaw(t, http.MethodDelete,
		"/api/v1/boxes/"+box.ID+"/files?path=/work", nil, "", un.SessionID)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBoxOwnershipIsolation(t *testing.T) {
	h1 := newHarness(t, "a@example.com", "password1")
	rr := h1.do(t, http.MethodPost, "/api/v1/boxes", CreateBoxRequest{
		Name: "alice-box", SizeBytes: 1024, Password: "boxpass1",
	}, "")
	var box BoxResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &box)

	boxes, _ := h1.vault.ListBoxes(context.Background(), "someone-else")
	if len(boxes) != 0 {
		t.Fatalf("expected 0 boxes for non-owner, got %d", len(boxes))
	}
	if _, err := h1.vault.UnlockBox(context.Background(), box.ID, "someone-else", "boxpass1"); err == nil {
		t.Fatal("expected authz error unlocking someone else's box")
	}
}
