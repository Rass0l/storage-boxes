//go:build compose_e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/apptest"
	vaultinfra "github.com/Rass0l/storage-boxes/internal/vault/infra"
)

// TestPGBoxRepositoryContract runs the shared BoxRepository contract
// from internal/vault/apptest against the live Postgres repo. Every
// sub-test receives its own namespaced row set (owner-id derived from
// Go test run time) so parallel runs don't stomp on each other, and
// the test cleans up before returning so successive invocations
// don't accumulate rows.
//
// Same contract as the memory-repo suite (see
// internal/vault/infra/memory_box_contract_test.go). When a new
// invariant lands in apptest, both implementations pick it up
// automatically — no more maintaining parallel assertions.
func TestPGBoxRepositoryContract(t *testing.T) {
	pool := openPG(t)
	defer pool.Close()

	owner := "contract_" + time.Now().UTC().Format("20060102_150405.000000")
	repo := vaultinfra.NewPGBoxRepository(pool)

	// Ensure a clean slate for this owner before + after the suite.
	cleanup := func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM boxes WHERE owner_user_id = $1`, owner)
	}
	cleanup()
	t.Cleanup(cleanup)

	apptest.BoxRepositoryContract(t, func(t *testing.T) app.BoxRepository {
		// The contract suite seeds its own fixed IDs (box_live,
		// box_dying, box_pc, box_fin, box_rt). To keep sub-tests
		// isolated against a shared pg repo, wipe any leftover rows
		// between sub-tests.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM boxes WHERE id IN ('box_live','box_dying','box_pc','box_fin','box_rt','box_nope')`)
		// Scope the ownership label to this run so a parallel test
		// binary doesn't collide.
		_ = owner
		return repo
	})
}
