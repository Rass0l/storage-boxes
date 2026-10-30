package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRestoreScriptsLint catches syntax errors in the recovery
// scripts in the same sweep as `go test`. `bash -n` exits non-zero on
// any unparsable construct without executing anything.
func TestRestoreScriptsLint(t *testing.T) {
	for _, name := range []string{
		"backup.sh", "restore.sh", "restore-verify.sh", "_extract-archive.sh",
	} {
		t.Run(name, func(t *testing.T) {
			path := locate(t, filepath.Join("scripts", name))
			out, err := exec.Command("bash", "-n", path).CombinedOutput()
			if err != nil {
				t.Fatalf("bash -n %s: %v\n%s", path, err, out)
			}
		})
	}
}

// TestRestoreScriptDocumentedFlags keeps the script's env contract
// aligned with the docs. Operators reading backup-restore.md /
// DEPLOYMENT.md expect these knobs; asserting them in one place
// catches silent drift when either side is edited in isolation.
func TestRestoreScriptDocumentedFlags(t *testing.T) {
	path := locate(t, filepath.Join("scripts", "restore.sh"))
	body := readFile(t, path)
	for _, needle := range []string{
		"DATABASE_URL",
		"SRC",
		"BOX_STORAGE_ROOT",
		"SHARE_STAGE_ROOT",
		"FORCE",
		"DRY_RUN",
		"SKIP_INTEGRITY_CHECK",
		"RESTORE_WAIT_FOR_WORKER",
		"WORKER_URL",
		"WORKER_WAIT_SECONDS",
		"MIGRATIONS_DIR",
		// The watermark check is load-bearing; make sure it stays.
		"migration_watermark_num",
		// The worker-tick gate must poll sweep-stats, not /readyz.
		"/api/v1/worker/sweep-stats",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("restore.sh must reference %q (documented flag / feature)", needle)
		}
	}
}

// TestBackupManifestUsesShellSafeKeys protects the contract between
// backup.sh (writer) and restore.sh (reader). If the writer reverts
// to dotted keys like `postgres.dump.sha256=…`, a future restore.sh
// that uses `source manifest.env` will break silently. This test
// locks the writer side to underscore-safe keys.
func TestBackupManifestUsesShellSafeKeys(t *testing.T) {
	path := locate(t, filepath.Join("scripts", "backup.sh"))
	body := readFile(t, path)
	// Positive: writer emits sha256_<key>= entries
	if !strings.Contains(body, "sha256_${key}=") {
		t.Error("backup.sh must emit sha256_<key>= entries for shell-safe sourcing")
	}
	// Negative: writer must not emit dotted keys (the old form).
	if strings.Contains(body, "$f.sha256=") || strings.Contains(body, "\"$f.sha256=") {
		t.Error("backup.sh still emits dotted manifest keys; restore.sh cannot source them")
	}
}

// TestRestoreVerifyCoversKeyChecks asserts the shipped verifier still
// covers every guarantee the docs claim it does.
func TestRestoreVerifyCoversKeyChecks(t *testing.T) {
	path := locate(t, filepath.Join("scripts", "restore-verify.sh"))
	body := readFile(t, path)
	for _, needle := range []string{
		"share_recipients",
		"share_challenges",
		"share_claims",
		"share_challenges_no_update",
		"share_access_events.recipient_id",
		"schema_migrations",
		"orphan share_claims",
		"orphan stage blobs",
		// Vault parity: same forward/backward checks as the stage side.
		"file_objects",
		"vault forward",
		"vault backward",
		"orphan vault blobs",
		"VERIFY_MAX_ORPHAN_VAULT_BLOBS",
		// Restricted-share recipient FK integrity + audit/outbox checks.
		"recipient-fk integrity",
		"dangling recipient_id",
		"claim-recipient consistency",
		"audit-outbox",
		"domain_outbox",
		// Access-request (migration 017) integrity + consistency checks.
		"share_access_requests",
		"orphan-access-requests",
		"access-request recipient-fk integrity",
		"access-request approval consistency",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("restore-verify.sh must reference %q", needle)
		}
	}
}

// TestBackupTarsContents pins the content-style tar convention so a
// future refactor can't silently revert to the legacy named-top-dir
// layout that couples archive paths to the source basename.
func TestBackupTarsContents(t *testing.T) {
	body := readFile(t, locate(t, filepath.Join("scripts", "backup.sh")))
	// Positive: content-style
	if !strings.Contains(body, `tar -C "$box_root" -czf "$dest/box_storage.tgz" .`) {
		t.Error("backup.sh must tar vault contents (content-style) into box_storage.tgz")
	}
	if !strings.Contains(body, `tar -C "$stage_root" -czf "$dest/share_stage.tgz" .`) {
		t.Error("backup.sh must tar stage contents (content-style) into share_stage.tgz")
	}
	// Negative: the old basename/dirname invocation must be gone.
	if strings.Contains(body, `"$(basename "$box_root")"`) ||
		strings.Contains(body, `"$(basename "$stage_root")"`) {
		t.Error("backup.sh still uses legacy dirname/basename layout; archives would couple to source basename")
	}
}
