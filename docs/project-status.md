# Project status

Version **0.5.0** is the initial repository baseline; no release is published.

Storage Boxes runs as a local Docker Compose application with persistent
PostgreSQL, encrypted file storage, temporary and restricted shares,
owner-approved access requests, an audit viewer, and background cleanup.

The current validation includes containerized Go lint/build/unit/integration
and migration checks, TypeScript checking, the frontend build, and 19 frontend
tests. A live smoke check covers encrypted file round-trips and the restricted
request -> approval -> verification -> delivery flow, denial, revocation, and
audit records. Stop/start persistence has also been checked.

## Remaining work

- Report request-persistence failures accurately instead of treating every
  insert failure as a duplicate request.
- Persist policy changes and audit/outbox events together, and surface worker
  failures instead of silently discarding them.
- Reconcile inconsistent recipient links and ensure request status reflects
  share availability and request expiry.
- Rehearse backup/restore into isolated volumes. The manifest's credential
  redaction is fixed; stopped writers/purgers are now documented as a snapshot
  precondition, which operators must enforce.
- Run the complete Compose acceptance and Playwright suites under an isolated
  project name and add them to CI.
- Replace manual box/file/unlock identifiers in the share form with a file
  selection workflow. Add account password-change support.

Local setup uses development mode and a computer-specific local CA on Windows.
The base Compose fallback remains self-signed and is not a browser trust setup.
Development OTP echo
remains available only in that mode. Shared deployment requires production
configuration, SMTP delivery for OTP, and trusted certificates. See
[DEPLOYMENT.md](../DEPLOYMENT.md) for configuration and recovery details.

The Go module uses `github.com/Rass0l/storage-boxes`, matching the
[public repository](https://github.com/Rass0l/storage-boxes).
The [public source review](publication-readiness.md) records the dependency
updates, current advisory scan results, and first-publication procedure.
