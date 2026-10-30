package infra

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

type NoopAccessRecorder struct{}

var _ app.ShareAccessRecorder = NoopAccessRecorder{}

func (NoopAccessRecorder) RecordAccess(ctx context.Context, event domain.AccessEvent) error {
	_ = ctx
	_ = event
	return nil
}

func (NoopAccessRecorder) ListByShare(ctx context.Context, shareID string, limit int) ([]domain.AccessEvent, error) {
	_ = ctx
	_ = shareID
	_ = limit
	return nil, nil
}

func (NoopAccessRecorder) ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.AccessEvent, error) {
	_ = ctx
	_ = recipientID
	_ = limit
	return nil, nil
}
