package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Migration 015 introduces share_recipients, share_challenges, and
// share_claims. Two non-negotiable guarantees we want in source control
// are asserted here so a future edit can't silently regress them:
//
//  1. share_challenges has a BEFORE UPDATE OR DELETE trigger calling
//     prevent_append_only_mutation() — matches share_access_events and
//     audit_events. Without this the verification log would be
//     rewritable and the audit trail would lose its "who tried what,
//     when" property.
//
//  2. shares.access_mode is a CHECK constraint over {public,restricted}.
//     An invalid value would let a restricted share be served as a
//     bearer link by the gateway; the check is the authoritative
//     validator since the domain enforcement is a soft pre-check.
//
// These are cheap file-level assertions so they run in the default
// `go test` sweep — no Postgres required.
func TestMigration015AppendOnlyTriggerOnShareChallenges(t *testing.T) {
	body := readMigration(t, "015_restricted_shares.up.sql")
	if !strings.Contains(body, "share_challenges_no_update") {
		t.Fatal("migration 015 must install share_challenges_no_update trigger")
	}
	if !strings.Contains(body, "prevent_append_only_mutation()") {
		t.Fatal("migration 015 must reference prevent_append_only_mutation()")
	}
	if !strings.Contains(body, "BEFORE UPDATE OR DELETE ON share_challenges") {
		t.Fatal("append-only trigger must cover both UPDATE and DELETE on share_challenges")
	}
}

func TestMigration015AccessModeCheckConstraint(t *testing.T) {
	body := readMigration(t, "015_restricted_shares.up.sql")
	if !strings.Contains(body, "access_mode") {
		t.Fatal("migration 015 must add shares.access_mode")
	}
	if !strings.Contains(body, "CHECK (access_mode IN ('public','restricted'))") {
		t.Fatal("shares.access_mode must enforce a CHECK constraint over {public,restricted}")
	}
}

func TestMigration015DownDropsNewTables(t *testing.T) {
	body := readMigration(t, "015_restricted_shares.down.sql")
	for _, needle := range []string{
		"DROP TABLE IF EXISTS share_claims",
		"DROP TABLE IF EXISTS share_challenges",
		"DROP TABLE IF EXISTS share_recipients",
		"DROP TRIGGER IF EXISTS share_challenges_no_update",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("down migration must include %q", needle)
		}
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	// Walk up from the test's CWD until we find the migrations/ dir, so
	// the test works whether invoked from the repo root or the package
	// directory.
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		path := filepath.Join(dir, "migrations", name)
		if b, err := os.ReadFile(path); err == nil {
			return string(b)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate migrations/%s", name)
	return ""
}
