# Public source review — 2026-10-30

Intended repository: `Rass0l/storage-boxes`, display name **Storage Boxes**.
Version: **0.5.0**, an initial evaluation baseline, not a production release.
The module path and imports now match that repository. No repository or release
is created by the source preparation scripts.

## Changes from the final review

- Updated Go builds to 1.27.3, pgx to 5.9.2, x/crypto to 0.56.0,
  x/sys to 0.47.0, x/text to 0.41.0, and required transitive modules.
- Updated React Router to 7.18.5, Vite to 7.3.7, Vitest to 4.1.12,
  the React Vite plugin to 5.2.0, Happy DOM to 21.0.4, and the npm lockfile.
- Updated Alpine runtime bases to 3.24.3 and nginx to 1.30.6.
- Refreshed third-party notices from installed dependency license files.
  The canonical Apache 2.0 license and project NOTICE remain intact.
- Pinned GitHub Actions to commit hashes, restricted CI to `contents: read`,
  disabled persisted checkout credentials, and added Go/npm advisory checks.
  Weekly Dependabot checks cover Go, npm, Dockerfiles, and Actions.
- Corrected the frontend container port and master-key generation example,
  and clarified the local database credentials and production setup boundary.

## Validation and interpretation

Backend formatting, vet, build, unit/integration/migration checks pass.
The frontend production build, TypeScript checks, and all 19 tests pass with
the updated router and tooling. The installed npm dependency tree reports zero
known vulnerabilities, including development dependencies.

The rebuilt local stack passes trusted HTTPS and the live sharing smoke flow,
including decryption of a sample stored before the rebuild. All five application
images contain byte-identical copies of the current license and notice files.

`govulncheck` reports zero vulnerabilities in imported packages or reachable
calls. It still reports one module-only advisory,
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), for the unused,
unmaintained OpenPGP package included in x/crypto. Storage Boxes does not import
that package. A clean reachable-call scan is not a complete security audit.

These results are a dated observation of the locked dependencies. CI queries
the live advisory databases and may report newly disclosed issues later.
Container bases have been refreshed, but a comprehensive OS-package image
scan and production hardening review remain separate work.

## First publication procedure

1. Run `scripts/prepare-repo.ps1` with any additional local credential files
   supplied through `-SecretEnvPath`. Publish the fresh filtered snapshot only.
   The exporter checks local credential values and runs offline Gitleaks.
2. Initialize a new Git history in that snapshot. Preserve shell executable
   bits as described in CONTRIBUTING.md and inspect the staged file list.
   Never import archived history, runtime data, dotenv credentials, or TLS keys.
3. Create the intended public repository without generated placeholder files,
   then push the reviewed initial commit. Never put a token in the remote URL.
4. Enable private vulnerability reporting, secret scanning/push protection,
   and dependency alerts where available. Protect the default branch against
   force-push/deletion and require the CI checks once the first run succeeds.
5. Confirm the public file listing, Apache license detection, and successful
   GitHub-hosted CI. Update SECURITY.md when private reporting is enabled.

The repository-level settings and hosted CI cannot be verified until the
repository exists. This review does not create it or grant a production-readiness
claim. Known audit durability, request consistency, full acceptance-suite, and
backup/restore gaps remain in [project status](project-status.md).

References: [Go vulnerability tooling](https://go.dev/doc/security/vuln/),
[GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use),
and [private vulnerability reports](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).
