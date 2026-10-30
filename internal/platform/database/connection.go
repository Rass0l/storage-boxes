package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connection wraps a live pgxpool.Pool plus parsed DSN metadata. The pool is
// nil when running with the `mem://local` DSN sentinel (docker-less tests),
// in which case PingContext is a no-op and callers must fall back to
// in-memory stores.
type Connection struct {
	DSN  string
	Meta DSNMetadata
	pool *pgxpool.Pool
}

// MemoryDSN is the sentinel DSN that keeps the app running entirely in
// memory. cmd/api uses this when no Postgres is configured — typically in
// unit and cross-package tests.
const MemoryDSN = "mem://local"

func Open(dsn string) (*Connection, error) {
	if dsn == MemoryDSN {
		return &Connection{DSN: dsn}, nil
	}
	meta, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx config: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pgx pool: %w", err)
	}
	conn := &Connection{DSN: dsn, Meta: meta, pool: pool}
	if err := conn.PingContext(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return conn, nil
}

// Pool returns the underlying pool. Nil when running in memory mode.
func (c *Connection) Pool() *pgxpool.Pool {
	if c == nil {
		return nil
	}
	return c.pool
}

// IsMemory reports whether this connection is the memory sentinel.
func (c *Connection) IsMemory() bool { return c != nil && c.pool == nil }

func (c *Connection) Close() error {
	if c == nil || c.pool == nil {
		return nil
	}
	c.pool.Close()
	return nil
}

func (c *Connection) PingContext(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("database connection is nil")
	}
	if c.pool == nil {
		return nil
	}
	return c.pool.Ping(ctx)
}
