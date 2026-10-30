package infra

import (
	"context"
	"fmt"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// NoopShareObjectStore exists so callers running outside the live
// share-gateway path (e.g. cross-package tests) can still register routes
// without a real stager. PutObject quietly succeeds and GetObject returns
// a sentinel not-found.
type NoopShareObjectStore struct{}

var _ app.ShareObjectStore = NoopShareObjectStore{}

func (NoopShareObjectStore) PutObject(ctx context.Context, object domain.ShareObject) error {
	_ = ctx
	_ = object
	return nil
}

func (NoopShareObjectStore) GetObject(ctx context.Context, shareID string) (domain.ShareObject, error) {
	_ = ctx
	_ = shareID
	return domain.ShareObject{}, fmt.Errorf("share object not found")
}

func (NoopShareObjectStore) DeleteObject(ctx context.Context, shareID string) error {
	_ = ctx
	_ = shareID
	return nil
}
