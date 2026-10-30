# Changelog

## 0.5.0 — Unreleased

Initial repository baseline. No release or tag has been published yet.

- Encrypted boxes, file/folder management, and PostgreSQL persistence.
- Temporary links and recipient-verified restricted sharing.
- Owner-approved recipient access requests, audit viewing, and worker cleanup.
- Windows Docker Compose launcher, persistent volumes, and local HTTPS.
- User-facing UI copy, current setup/use-case documentation, and source export
  checks for secrets.
- Apache 2.0 project licensing and attribution files.
- Patched Go and frontend dependencies, Go 1.27.3 builds, dependency audits in
  CI, and weekly dependency update checks. CI uses read-only repository access.
- Computer-specific Windows TLS setup and startup certificate checks; local
  CA keys are excluded from source export and Docker build contexts.

Known correctness and recovery gaps are tracked in
[project status](docs/project-status.md). This baseline is not a claim of
production readiness or a security certification.
