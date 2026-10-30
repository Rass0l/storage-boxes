package infra_test

import (
	"testing"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/apptest"
	"github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestMemoryBoxRepositoryContract runs the shared behavioral contract
// against the memory repo. The same contract is run against the pg
// repo in compose_pg_direct tests (see test/e2e) — a single source of
// truth replacing the former SQL-string grep.
func TestMemoryBoxRepositoryContract(t *testing.T) {
	apptest.BoxRepositoryContract(t, func(t *testing.T) app.BoxRepository {
		return infra.NewMemoryBoxRepository()
	})
}
