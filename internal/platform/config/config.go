package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Rass0l/storage-boxes/internal/platform/security"
)

type Config struct {
	AppEnv           string
	APIAddr          string
	WorkerAddr       string
	ShareGatewayAddr string
	HealthAddr       string
	DatabaseURL      string
	ServerMasterKey  string

	// Operational hardening fields. Loaded in addition to the legacy set so
	// existing callers don't need to change.
	TrustedProxies []string
	ShareStageRoot string
	BoxStorageRoot string
	PublicBaseURL  string
	RequireTLS     bool

	// Restricted-share OTP delivery. When OTPSMTPAddr and OTPSMTPFrom are
	// both set, the binaries wire an email-based OTPDispatcher so
	// require_otp shares are operable (the one-time code is delivered
	// out-of-band, never returned in a response or logged). Username /
	// password enable SMTP PLAIN auth. Left empty, require_otp shares are
	// rejected at create time outside dev (DevModeOTPEcho).
	OTPSMTPAddr     string
	OTPSMTPFrom     string
	OTPSMTPUsername string
	OTPSMTPPassword string
}

// Load reads the runtime configuration from env vars and enforces the
// production-only invariants: DATABASE_URL is always required;
// SERVER_MASTER_KEY must be a 64-hex (32-byte) string when APP_ENV is
// "production" or "staging"; trusted proxy CIDRs must parse.
func Load() (Config, error) {
	cfg := Config{
		AppEnv:           os.Getenv("APP_ENV"),
		APIAddr:          getenv("API_ADDR", ":8082"),
		WorkerAddr:       getenv("WORKER_ADDR", ":8083"),
		ShareGatewayAddr: getenv("SHARE_GATEWAY_ADDR", ":8084"),
		HealthAddr:       getenv("HEALTH_ADDR", ":8090"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		ServerMasterKey:  os.Getenv("SERVER_MASTER_KEY"),
		ShareStageRoot:   getenv("SHARE_STAGE_ROOT", "./.share-stage"),
		BoxStorageRoot:   getenv("BOX_STORAGE_ROOT", "./.box-storage"),
		PublicBaseURL:    os.Getenv("SHARE_PUBLIC_BASE_URL"),
		OTPSMTPAddr:      os.Getenv("SHARE_OTP_SMTP_ADDR"),
		OTPSMTPFrom:      os.Getenv("SHARE_OTP_SMTP_FROM"),
		OTPSMTPUsername:  os.Getenv("SHARE_OTP_SMTP_USERNAME"),
		OTPSMTPPassword:  os.Getenv("SHARE_OTP_SMTP_PASSWORD"),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if tp := os.Getenv("TRUSTED_PROXIES"); tp != "" {
		for _, part := range strings.Split(tp, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				cfg.TrustedProxies = append(cfg.TrustedProxies, p)
			}
		}
	}
	if IsProductionLike(cfg.AppEnv) {
		if err := security.ValidateMasterKeyHex(cfg.ServerMasterKey); err != nil {
			return Config{}, fmt.Errorf("SERVER_MASTER_KEY invalid for %q: %w", cfg.AppEnv, err)
		}
		cfg.RequireTLS = true
	}
	return cfg, nil
}

// IsProductionLike returns true for environments where the stricter posture
// (HTTPS cookies, master-key validation, trusted proxies required) applies.
func IsProductionLike(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod", "staging":
		return true
	}
	return false
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func MustInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
