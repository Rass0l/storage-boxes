# ADR-003: Go Dependency Vendoring Policy

## Status
Accepted with staged rollout

## Context
The implementation spec recommends vendoring backend dependencies early so CI and local builds are reproducible. The Stage 1 scaffold was intentionally built with a near-stdlib baseline to stabilize repository shape before introducing external crypto, database, or middleware packages.

## Decision
Stage 1 keeps the backend dependency-light and does not commit `vendor/` yet. The repository still prepares for vendoring by:
- isolating platform concerns behind stable interfaces
- keeping runtime config and database boot centralized
- documenting the first dependency wave required for Stage 2 and Stage 3

The first vendored dependency set should include:
- `github.com/jackc/pgx/v5` for PostgreSQL
- `golang.org/x/crypto` for Argon2id and related primitives
- any chosen request/middleware helpers only if they survive review

## Consequences
### Positive
- the Stage 1 tarball stays compact and readable
- core structure remains reviewable without a large third-party footprint

### Negative
- Stage 1 does not yet prove vendor-based builds
- Stage 2 must explicitly flip CI and local build docs to `-mod=vendor` once external dependencies are committed
