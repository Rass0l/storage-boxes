# Storage Boxes

Version **0.5.0** — initial repository baseline, not yet published as a release.
See [CHANGELOG.md](CHANGELOG.md) and [VERSION](VERSION).

Self-hosted encrypted file storage with expiring links, verified recipients,
and owner-approved access requests.

Storage Boxes lets you organize files in password-protected boxes and control
how they are shared. It runs as a Docker Compose stack with a React interface,
a Go API, a separate share gateway, a background worker, and PostgreSQL.

## Features

- Create, unlock, and manage encrypted boxes, files, and folders.
- Share files through temporary links with expiry and download limits.
- Restrict delivery to recipients who verify with a passcode, with optional
  email-delivered one-time codes.
- Review and approve or deny access requests from new recipients. Approval
  adds recipient access; verification is still required before downloading.
- Revoke shares, recipients, and verified sessions.
- Inspect sharing activity and audit records in the web interface.
- Run background expiry, reconciliation, and cleanup jobs against stored state.

Encryption is performed by the server. This project does not implement
end-to-end encryption or a zero-knowledge storage model.

## Use cases

| Use case | Current workflow |
| --- | --- |
| Personal or internal file workspace | Keep files in password-protected boxes; unlock a box to upload, organize, or download its contents. |
| Time-limited file handoff | Create a temporary link with an expiry and download limit. Anyone holding that link can use it while it remains available. |
| Sharing with selected recipients | Use a restricted share and send each recipient their passcode separately. Revocation blocks later downloads. |
| Owner-reviewed access | Let an unlisted visitor request access, then approve or deny it. An approved visitor must still verify before downloading. |
| Activity review | Inspect share access, recipient activity, and decisions in the audit interface. This is not a compliance certification or a guaranteed complete audit trail. |

This baseline fits local evaluation and internal workflow development. Share
creation currently uses box/file identifiers and an unlock-session identifier;
it does not yet have an integrated file picker. Account password changes are
also not available in the interface.

## Quick start on Windows

Install Docker Desktop with the Linux containers engine, Docker Compose
2.24.4 or newer, PowerShell 7.2 or newer, and
[mkcert](https://github.com/FiloSottile/mkcert). Prepare HTTPS before the first start:

```powershell
.\scripts\setup-local-tls.ps1
# Review the printed local CA thumbprint before choosing to trust it.
.\scripts\setup-local-tls.ps1 -Activate -TrustCurrentUser
.\scripts\windows-stack.ps1 Start
```

Open [https://localhost:18443/login](https://localhost:18443/login). The Windows
launcher checks certificate validity, localhost naming, key matching, and OS
trust before starting. See [trusted local HTTPS setup](WINDOWS.md#trusted-local-https)
for certificate renewal, Firefox checks, and migration from old archives.
HTTP on port 18088 redirects to HTTPS. Both
ports bind only to your computer's loopback interface.

The first start generates `.env.windows` with a random server master key and
administrator password. Use the account email in `SEED_ADMIN_EMAIL` and the
password in `SEED_ADMIN_PASSWORD` from that local file. Do not commit or share
it. Keep the master key with your protected backups: encrypted data cannot be
recovered without it.

```powershell
.\scripts\windows-stack.ps1 Status  # Container health
.\scripts\windows-stack.ps1 Logs    # Recent service logs
.\scripts\windows-stack.ps1 Stop    # Stop while retaining data
.\scripts\windows-stack.ps1 Start   # Rebuild/start with existing settings
```

Go, Node.js, Bash, and PostgreSQL do not need to be installed on Windows.
See [WINDOWS.md](WINDOWS.md) for ports, configuration, persistence, and checks.

## How sharing works

Temporary links allow anyone holding the link to download while its expiry and
download limits permit it. Restricted links require a recipient-specific
passcode and a verified session. An optional one-time code adds email
verification when SMTP delivery is configured in production. Recipients who
are not on the allowed list can request access;
the owner reviews the request and provides a passcode after approval.

Public request endpoints return only coarse request status. They do not return
owner details, internal identifiers, private file metadata, or passcodes.

## Stack and persistence

| Service | Responsibility |
| --- | --- |
| Edge | HTTPS entry point and routing |
| Frontend | React and TypeScript interface |
| API | Accounts, sessions, boxes, files, and share management |
| Share gateway | Public verification, access requests, and downloads |
| Worker | Expiry, reconciliation, cleanup, and outbox dispatch |
| PostgreSQL | Metadata, recipient policy, requests, sessions, and audit state |
| Migrate | One-shot schema migrations before services start |

The Windows stack publishes only the edge. Database state, encrypted vault
blobs, and staged share content use separate persistent named volumes. Stopping
the stack keeps those volumes. Commands containing `down -v` remove them.

File names, paths, account details, and audit metadata are visible to the
server. Protect the database and both storage volumes as well as the master
key. An application version of 0.5.0 does not change the `/api/v1` route prefix.

## Checks

Run backend and frontend checks in disposable containers:

```powershell
.\scripts\windows-stack.ps1 Check
```

Check also verifies the application version, Apache license text, notice files,
and image version metadata. These checks run in CI as well.
CI additionally checks known dependency advisories with `govulncheck` and
`npm audit`; see [CONTRIBUTING.md](CONTRIBUTING.md) for the commands.

Exercise the running stack's login, encrypted storage, sharing, access requests,
and audit paths:

```powershell
.\scripts\windows-stack.ps1 Smoke
```

Smoke creates a small sample box and checks that a previous sample remains
readable. The separate Compose acceptance harness deletes its test project's
volumes; run it only against an isolated project. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the source workflow and additional suites.

## Preparing source for a repository

Export only Git-eligible source files and scan the result locally:

```powershell
.\scripts\prepare-repo.ps1
```

This creates a new source snapshot outside the working project, checks for
local credential values, and runs a pinned
[Gitleaks](https://github.com/gitleaks/gitleaks) image without network access.
It does not create a repository or push anything. Use `-SecretEnvPath` to check
credentials stored in additional env files. Local env files, private keys,
backups, runtime data, and compiled binaries are excluded. Only `.env.example`
and `.env.test.example` are intended for source control.

## Status and documentation

The current local stack has passed backend checks, the frontend build and 19
frontend tests, live sharing smoke checks, and a stop/start persistence check.
[Project status](docs/project-status.md) records the remaining correctness and
recovery work, including audit durability and a full backup/restore rehearsal.
Share creation currently requires source identifiers and an unlock session;
an integrated file picker and account password changes remain future work.

Local mode includes development OTP echo and uses a computer-specific local CA. Before a
shared deployment, configure production mode, trusted certificates, unique
credentials, and SMTP. Treat the recovery procedures as needing validation
for your deployment rather than assuming the local smoke check proves them.

- [Deployment and configuration](DEPLOYMENT.md)
- [API routes](docs/api/routes.md) and [OpenAPI](api/openapi/README.md)
- [Sharing behavior](docs/implementation/shares.md)
- [Audit model](docs/implementation/audit.md)
- [Backup and restore](docs/implementation/backup-restore.md)
- [Architecture decisions](docs/adr/)
- [Security reporting and deployment boundary](SECURITY.md)
- [Licensing and attribution](docs/licensing.md)

## License

Copyright 2026 Storage Boxes contributors.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for project attribution and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for
application dependency notices. The license includes its standard warranty
disclaimer and liability limits; see sections 7 and 8 of LICENSE.
