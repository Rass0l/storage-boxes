package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := applyMigrations(cfg.DatabaseURL, "./migrations"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("migrations applied")
}

func applyMigrations(dsn, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}
	files := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })

	bootstrap := `CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`
	if err := runPSQL(dsn, bootstrap); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	applied, err := listAppliedVersions(dsn)
	if err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}

	for _, entry := range files {
		version := strings.TrimSuffix(entry.Name(), ".up.sql")
		if applied[version] {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := runPSQLFile(dsn, path); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		insertSQL := fmt.Sprintf("INSERT INTO schema_migrations(version) VALUES ('%s')", escapeLiteral(version))
		if err := runPSQL(dsn, insertSQL); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}

func listAppliedVersions(dsn string) (map[string]bool, error) {
	cmd := exec.Command("psql", dsn, "-X", "-q", "-t", "-A", "-c", "SELECT version FROM schema_migrations ORDER BY version")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("psql failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	versions := map[string]bool{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		v := strings.TrimSpace(line)
		if v == "" {
			continue
		}
		versions[v] = true
	}
	return versions, nil
}

func runPSQL(dsn, sqlText string) error {
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-c", sqlText)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runPSQLFile(dsn, path string) error {
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-f", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func escapeLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
