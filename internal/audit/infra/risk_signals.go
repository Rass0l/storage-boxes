package infra

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

type NoopRiskSignalRepository struct{}

var _ app.RiskSignalRepository = NoopRiskSignalRepository{}

func (NoopRiskSignalRepository) PutSignal(ctx context.Context, signal domain.RiskSignal) error {
	_ = ctx
	_ = signal
	return nil
}

func (NoopRiskSignalRepository) ListBySubject(ctx context.Context, subjectType, subjectID string) ([]domain.RiskSignal, error) {
	_ = ctx
	_ = subjectType
	_ = subjectID
	return nil, nil
}
