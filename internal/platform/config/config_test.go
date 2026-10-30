package config

import (
	"strings"
	"testing"
)

func TestMustIntFallback(t *testing.T) {
	if got := MustInt("STAGE1_UNKNOWN", 42); got != 42 {
		t.Fatalf("expected fallback, got %d", got)
	}
}

func TestLoadRejectsShortMasterKeyInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
	t.Setenv("SERVER_MASTER_KEY", "deadbeef")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SERVER_MASTER_KEY") {
		t.Fatalf("expected master key error, got %v", err)
	}
}

func TestLoadAcceptsValidMasterKeyInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
	// 64 hex chars = 32 bytes.
	t.Setenv("SERVER_MASTER_KEY", strings.Repeat("ab", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if !cfg.RequireTLS {
		t.Fatal("expected RequireTLS in production")
	}
}

func TestLoadAllowsMissingMasterKeyInDev(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
	t.Setenv("SERVER_MASTER_KEY", "")
	if _, err := Load(); err != nil {
		t.Fatalf("expected dev load to succeed, got %v", err)
	}
}

func TestLoadParsesTrustedProxies(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 127.0.0.1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("want 2 proxies, got %v", cfg.TrustedProxies)
	}
}
