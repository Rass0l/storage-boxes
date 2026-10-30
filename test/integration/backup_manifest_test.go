package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Drive the real backup script with an isolated dump stub. This verifies the
// emitted artifact rather than only inspecting a redaction expression.
func TestBackupManifestDoesNotExposeDatabaseCredentials(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	box := filepath.Join(root, "boxes")
	stage := filepath.Join(root, "shares")
	dest := filepath.Join(root, "backup")
	for _, dir := range []string{bin, box, stage} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "pg_dump"), []byte("#!/usr/bin/env bash\nprintf 'test dump\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	password := strings.Repeat("b", 24)
	dsn := "postgres://backup-user:" + password + "@db.invalid/backup_test?sslmode=disable"
	cmd := exec.Command("bash", locate(t, filepath.Join("scripts", "backup.sh")))
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DATABASE_URL="+dsn, "BOX_STORAGE_ROOT="+box, "SHARE_STAGE_ROOT="+stage, "DEST="+dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	manifest, err := os.ReadFile(filepath.Join(dest, "manifest.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), password) || strings.Contains(string(manifest), "backup-user") ||
		strings.Contains(string(out), password) {
		t.Fatal("backup emitted database credentials")
	}
	for _, key := range []string{"database_url_redacted=redacted", "sha256_postgres_dump=", "sha256_box_storage_tgz=", "sha256_share_stage_tgz="} {
		if !strings.Contains(string(manifest), key) {
			t.Errorf("missing manifest field %s", key)
		}
	}
}
