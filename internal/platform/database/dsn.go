package database

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type DSNMetadata struct {
	Scheme   string
	Host     string
	Port     string
	User     string
	Database string
	SSLMode  string
}

func ParseDSN(dsn string) (DSNMetadata, error) {
	if dsn == "" {
		return DSNMetadata{}, fmt.Errorf("database dsn is required")
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return DSNMetadata{}, fmt.Errorf("parse database dsn: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return DSNMetadata{}, fmt.Errorf("unsupported database scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return DSNMetadata{}, fmt.Errorf("database host is required")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" {
		return DSNMetadata{}, fmt.Errorf("database name is required")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return DSNMetadata{}, fmt.Errorf("invalid database port %q: %w", port, err)
	}
	return DSNMetadata{
		Scheme:   u.Scheme,
		Host:     host,
		Port:     port,
		User:     u.User.Username(),
		Database: database,
		SSLMode:  u.Query().Get("sslmode"),
	}, nil
}
