package app

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type CryptoStore interface {
	Put(ctx context.Context, material domain.BoxCryptoMaterial) error
	Get(ctx context.Context, boxID string) (domain.BoxCryptoMaterial, error)
	Delete(ctx context.Context, boxID string) error
}
