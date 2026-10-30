package app_test

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
	"github.com/Rass0l/storage-boxes/internal/shares/infra"
)

// TestTokenIsOneShot proves the raw capability token is only exposed via
// the CreateShare result. Neither the domain.Share struct persisted nor
// the ShareResponse returned by Get or List carries the raw token — only
// the hash. If a field named /token/i ever appears on the Share domain
// type, this test will fail.
func TestTokenIsOneShot(t *testing.T) {
	// Domain must not expose a raw token field.
	st := reflect.TypeOf(domain.Share{})
	for i := 0; i < st.NumField(); i++ {
		name := strings.ToLower(st.Field(i).Name)
		if name == "token" || name == "rawtoken" {
			t.Fatalf("domain.Share must not expose %q", st.Field(i).Name)
		}
	}

	// Create path returns the raw token once.
	svc, shareID, token := buildServiceAndCreate(t)
	if token == "" {
		t.Fatal("expected raw token in CreateShare result")
	}

	// Get path never returns it.
	got, err := svc.Get(context.Background(), "usr_t", shareID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TokenHash == "" {
		t.Fatal("persisted share must carry a token hash")
	}
	if strings.Contains(got.TokenHash, token) {
		t.Fatal("token hash must not embed the raw token verbatim")
	}

	// ResolveByToken accepts the raw and returns the matching share.
	resolved, err := svc.ResolveByToken(context.Background(), token)
	if err != nil || resolved.ID != shareID {
		t.Fatalf("resolve: %v id=%s", err, resolved.ID)
	}

	// A wrong token returns not_found (not "share not available") —
	// the service must not leak existence through timing or messaging.
	if _, err := svc.ResolveByToken(context.Background(), token+"x"); err == nil {
		t.Fatal("expected not found for wrong token")
	}
}

func buildServiceAndCreate(t *testing.T) (*app.Service, string, string) {
	t.Helper()
	shareRepo := infra.NewMemoryShareRepository()
	objStore := infra.NewMemoryShareObjectStore()
	access := infra.NewMemoryAccessRecorder()
	stage := stubStageEngine{}
	files := stubFileLookup{}
	svc := app.NewService(app.Deps{
		Shares:    shareRepo,
		Objects:   objStore,
		AccessLog: access,
		Files:     files,
		Stage:     stage,
		Tokens:    infra.RandomTokenService{},
	})
	result, err := svc.CreateShare(context.Background(), app.CreateShareInput{
		CreatorUserID: "usr_t", BoxID: "b", FileEntryID: "f",
		UnlockBMK: []byte("bmkbmkbmkbmkbmkbmkbmkbmkbmkbmkbm"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), MaxDownloads: 2,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return svc, result.Share.ID, result.RawToken
}

// stubStageEngine returns a fixed payload without touching disk, so the
// token-secrecy test can run without a vault.
type stubStageEngine struct{}

func (stubStageEngine) Stage(ctx context.Context, boxID, fileID string, bmk []byte) (app.StagedPayload, error) {
	return app.StagedPayload{
		StorageKey: "sk", WrappedShareKey: []byte("abcdefghijkl"), Nonce: []byte("012345678901"),
		SizeBytes: 4, ContentType: "text/plain", OriginalName: "f.txt",
	}, nil
}
func (stubStageEngine) Delete(ctx context.Context, shareID, storageKey string) error { return nil }
func (stubStageEngine) Open(ctx context.Context, sk string, wsk, nonce []byte) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

type stubFileLookup struct{}

func (stubFileLookup) LookupFile(ctx context.Context, boxID, fileID string) (app.FileMeta, error) {
	return app.FileMeta{Name: "f.txt", ContentType: "text/plain", SizeBytes: 4}, nil
}
