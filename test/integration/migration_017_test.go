package integration

import (
	"strings"
	"testing"
)

// Migration 017 introduces share_access_requests, the mutable table backing
// owner-approved recipient access requests. The guarantees pinned here so a
// future edit can't silently regress them:
//
//  1. The status CHECK constraint covers exactly the lifecycle vocabulary
//     {pending,approved,denied,expired,superseded}. An out-of-band status
//     would let the worker / service drift from the documented state machine.
//  2. A PARTIAL UNIQUE INDEX dedupes pending requests per (share, email)
//     while still allowing terminal history rows and a legitimate re-request.
//     This is also the race backstop for concurrent submits.
//  3. recipient_id is ON DELETE SET NULL (not CASCADE), so a share purge that
//     hard-deletes recipient rows leaves approved-request history intact.
//  4. share_id is ON DELETE CASCADE so a hard-deleted share takes its
//     requests with it (no orphans).
//
// These are cheap file-level assertions so they run in the default
// `go test` sweep — no Postgres required.
func TestMigration017AccessRequestStatusCheck(t *testing.T) {
	body := readMigration(t, "017_share_access_requests.up.sql")
	if !strings.Contains(body, "CREATE TABLE IF NOT EXISTS share_access_requests") {
		t.Fatal("migration 017 must create share_access_requests")
	}
	if !strings.Contains(body, "CHECK (status IN ('pending','approved','denied','expired','superseded'))") {
		t.Fatal("share_access_requests.status must enforce the full lifecycle CHECK constraint")
	}
}

func TestMigration017PendingPartialUniqueIndex(t *testing.T) {
	body := readMigration(t, "017_share_access_requests.up.sql")
	if !strings.Contains(body, "CREATE UNIQUE INDEX IF NOT EXISTS uq_share_access_requests_pending") {
		t.Fatal("migration 017 must create the pending partial unique index")
	}
	if !strings.Contains(body, "WHERE status = 'pending'") {
		t.Fatal("the pending uniqueness must be a PARTIAL index over status='pending'")
	}
}

func TestMigration017ForeignKeys(t *testing.T) {
	body := readMigration(t, "017_share_access_requests.up.sql")
	if !strings.Contains(body, "REFERENCES shares(id) ON DELETE CASCADE") {
		t.Fatal("share_access_requests.share_id must cascade-delete with its share")
	}
	if !strings.Contains(body, "REFERENCES share_recipients(id) ON DELETE SET NULL") {
		t.Fatal("share_access_requests.recipient_id must be ON DELETE SET NULL to preserve approval history")
	}
}

func TestMigration017DownDropsTable(t *testing.T) {
	body := readMigration(t, "017_share_access_requests.down.sql")
	if !strings.Contains(body, "DROP TABLE IF EXISTS share_access_requests") {
		t.Fatal("down migration must drop share_access_requests")
	}
}
