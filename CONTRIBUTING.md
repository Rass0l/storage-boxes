# Contributing

Current repository version: **0.5.0**. Keep `VERSION`, the root package/lockfile
versions, OpenAPI `info.version`, image version labels, and current operator
docs in agreement. Dependency versions and the `/api/v1` route prefix are
independent of the application version.

## Local workflow

On Windows, use PowerShell 7.2 or newer, complete the local TLS setup in
[WINDOWS.md](WINDOWS.md#trusted-local-https), then run
`.\scripts\windows-stack.ps1 Start` from the repository root.
Use `Status` and `Logs` to inspect the stack, and `Stop` to stop it while retaining
its volumes. See [WINDOWS.md](WINDOWS.md) for generated credentials and ports.

For the base Linux Compose workflow, follow [DEPLOYMENT.md](DEPLOYMENT.md).
Copy `.env.example` to `.env` and set a unique master key and administrator
password before starting. The example intentionally leaves the master key empty.
Never reuse the synthetic key from `.env.test.example` for stored user data.

## Checks

The Windows wrapper runs the existing checks with the container toolchains:

```powershell
.\scripts\windows-stack.ps1 Check
.\scripts\windows-stack.ps1 Smoke
```

Check includes Go formatting, vet, build, unit/integration/migration checks,
TypeScript checking, and Vitest. Smoke requires the running stack and creates
sample data while exercising real persistence and sharing paths.

With Go, Node.js, and Bash installed, the source equivalents are:

Use Go 1.27.3 and Node.js 22.18 or newer in the Node 22 line. The frontend
build/test tools require a modern Node 22 runtime; CI selects the latest Node 22.

```bash
bash scripts/ci-verify.sh
cd web
npm ci --no-fund --no-audit
npm run typecheck
npm test
npm run build
```

CI also runs `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` at the
repository root and `npm audit --audit-level=low` in `web`. These checks query
public advisory databases and require network access. Weekly Dependabot checks
cover Go, npm, Dockerfiles, and GitHub Actions.

The separate `make compose-e2e` suite starts and destroys its own stack. Set an
isolated `COMPOSE_PROJECT_NAME` and use disposable volumes; its harness calls
`down -v`. `make compose-ui-e2e` runs Playwright against a running stack. These
acceptance suites are separate from Check and Smoke.

## Before publishing source

```powershell
.\scripts\prepare-repo.ps1
```

The exporter respects `.gitignore`, rejects runtime and credential files even
if tracked, checks candidate files for local secret values, and scans a new
snapshot with a pinned Gitleaks container. To include additional credential
files in the exact-match check, pass `-SecretEnvPath` with their local paths.
Only the filtered snapshot is mounted into the offline scanner. No commit or
push is made, and findings are redacted.

Review the snapshot before the initial commit. Keep actual env files, private
keys, backups, runtime data, logs, and compiled binaries out of source control.
The example env files and fixtures contain synthetic values only. The project
uses the [Apache License 2.0](LICENSE); preserve [NOTICE](NOTICE) and any
applicable third-party attribution when redistributing it.

When initializing Git from a Windows snapshot, preserve executable script bits
in the initial index after staging the files:

```powershell
Get-ChildItem scripts -Filter *.sh | ForEach-Object { git update-index --chmod=+x ("scripts/" + $_.Name) }
git update-index --chmod=+x .githooks/pre-commit
```

Backend CI invokes Bash explicitly so it can also run from a Windows-created
checkout without executable bits. Keep authentication
tokens in a credential helper or process environment, never in remote URLs.

## Conventions

Intentional contributions are offered under Apache 2.0 as described in section
5 of [LICENSE](LICENSE), unless a separate agreement applies. Contributors
retain their copyrights. Keep third-party attribution intact, identify the
origin/license of reused code, and refresh [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
when dependencies change. Report security problems through [SECURITY.md](SECURITY.md).

- Keep module boundaries under `internal/` and decisions under `docs/adr/`.
- Authenticated routes live under `/api/v1/`; public sharing uses `/s/`.
- Vault operations require a user-bound unlock session.
- Update API docs and tests when changing behavior.
- Keep implementation details in contributor/operator documentation and use
  plain, task-oriented wording in the interface.
