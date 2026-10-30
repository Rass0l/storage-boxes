// Package apptest holds cross-package test helpers for vault
// implementations. The contract in this file is the single source of
// truth for behavioral parity between BoxRepository implementations
// (memory, Postgres, anything else). The memory-repo unit tests and
// the pg-direct compose tests import it and hand in a factory.
//
// Kept out of internal/vault/app itself so the testing-only code
// doesn't drag `testing` into production builds.
package apptest

import (
	"context"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// BoxRepositoryContract runs every check a BoxRepository must pass.
// The factory is called per sub-test so implementations can seed a
// fresh, empty repo each time.
func BoxRepositoryContract(t *testing.T, makeRepo func(t *testing.T) app.BoxRepository) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutGetRoundtrip", func(t *testing.T) {
		repo := makeRepo(t)
		box := domain.Box{
			ID: "box_rt", OwnerUserID: "u", Name: "rt", SizeBytes: 64, Status: "active",
			CreatedAt: time.Now().UTC().Truncate(time.Second),
		}
		if err := repo.Put(ctx, box); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Get(ctx, box.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != box.ID || got.OwnerUserID != box.OwnerUserID ||
			got.Name != box.Name || got.Status != box.Status {
			t.Fatalf("round-trip mismatch: want %+v got %+v", box, got)
		}
	})

	// ListByOwner must filter `status='deleting'`. This is the contract
	// the docs spell out and the primary place pg + memory used to
	// diverge: pg historically returned deleting rows here. A SQL-
	// string grep caught literal drift only — this exercises the
	// actual filter behavior.
	t.Run("ListByOwnerHidesDeleting", func(t *testing.T) {
		repo := makeRepo(t)
		now := time.Now().UTC()
		live := domain.Box{ID: "box_live", OwnerUserID: "u", Name: "live", SizeBytes: 1, Status: "active", CreatedAt: now.Add(-time.Minute)}
		dying := domain.Box{ID: "box_dying", OwnerUserID: "u", Name: "dying", SizeBytes: 1, Status: "active", CreatedAt: now}
		if err := repo.Put(ctx, live); err != nil {
			t.Fatal(err)
		}
		if err := repo.Put(ctx, dying); err != nil {
			t.Fatal(err)
		}
		if err := repo.SoftDelete(ctx, dying.ID, now); err != nil {
			t.Fatal(err)
		}
		rows, err := repo.ListByOwner(ctx, "u")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.ID == dying.ID {
				t.Fatalf("soft-deleted box %q must not appear in ListByOwner", r.ID)
			}
		}
		sawLive := false
		for _, r := range rows {
			if r.ID == live.ID {
				sawLive = true
			}
		}
		if !sawLive {
			t.Fatalf("active box %q missing from ListByOwner", live.ID)
		}
	})

	// SoftDelete flips status and the worker can still see the row via
	// ListPurgeCandidates — otherwise BoxPurgeJob would starve.
	t.Run("SoftDeleteSurfacesToPurgeCandidates", func(t *testing.T) {
		repo := makeRepo(t)
		now := time.Now().UTC()
		box := domain.Box{ID: "box_pc", OwnerUserID: "u", Name: "pc", SizeBytes: 1, Status: "active", CreatedAt: now}
		if err := repo.Put(ctx, box); err != nil {
			t.Fatal(err)
		}
		if err := repo.SoftDelete(ctx, box.ID, now); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Get(ctx, box.ID)
		if err != nil {
			t.Fatalf("soft-deleted row must remain Get-able: %v", err)
		}
		if got.Status != "deleting" {
			t.Fatalf("status: want deleting, got %q", got.Status)
		}
		candidates, err := repo.ListPurgeCandidates(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range candidates {
			if c.ID == box.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("ListPurgeCandidates must surface soft-deleted rows")
		}
	})

	t.Run("SoftDeleteUnknownReturnsError", func(t *testing.T) {
		repo := makeRepo(t)
		if err := repo.SoftDelete(ctx, "box_nope", time.Now().UTC()); err == nil {
			t.Fatal("expected error on unknown id")
		}
	})

	t.Run("FinalizeDeleteRemovesRow", func(t *testing.T) {
		repo := makeRepo(t)
		now := time.Now().UTC()
		box := domain.Box{ID: "box_fin", OwnerUserID: "u", Name: "fin", SizeBytes: 1, Status: "active", CreatedAt: now}
		if err := repo.Put(ctx, box); err != nil {
			t.Fatal(err)
		}
		if err := repo.SoftDelete(ctx, box.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := repo.FinalizeDelete(ctx, box.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, box.ID); err == nil {
			t.Fatal("Get must fail after FinalizeDelete")
		}
		candidates, _ := repo.ListPurgeCandidates(ctx, 10)
		for _, c := range candidates {
			if c.ID == box.ID {
				t.Fatal("FinalizeDelete must remove the row from ListPurgeCandidates")
			}
		}
	})
}
