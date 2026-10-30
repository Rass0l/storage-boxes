# Windows Docker Compose

Applies to Storage Boxes **0.5.0**. Use PowerShell 7.2 or newer, Docker Desktop
in Linux containers mode, Docker Compose 2.24.4 or newer, and
[mkcert from its official project](https://github.com/FiloSottile/mkcert).
Host Go, Node.js, Bash, and PostgreSQL installations are not needed.

## Trusted local HTTPS

Complete this before the first Start. Each computer must generate its own CA
and localhost certificate; the repository intentionally contains no TLS keys.

```powershell
.\scripts\setup-local-tls.ps1
```

Pass `-MkcertPath 'C:\path\to\mkcert.exe'` if the executable is not on PATH.
Preparation generates `.local-ca/rootCA.pem` and its private key, plus pending
localhost certificate/key files under `deployments/compose/edge/tls`. It prints
the CA thumbprint and validity dates. It changes neither trust nor the active
server certificate.

Review the thumbprint before explicitly choosing to trust this CA for your
Windows user and activate the prepared certificate:

```powershell
.\scripts\setup-local-tls.ps1 -Activate -TrustCurrentUser
.\scripts\check-local-tls.ps1
.\scripts\windows-stack.ps1 Start
```

The trust step adds the CA to `Cert:\CurrentUser\Root`; it does not alter other
existing certificates. The CA private key can issue certificates trusted by
this user. Keep it private. Its directory is restricted to the current user,
SYSTEM, and administrators. `.local-ca` is excluded from Git, source export,
and Docker builds and is never mounted into the edge. Only the localhost
leaf certificate/key is mounted there.

Start checks certificate dates, localhost DNS naming, key matching, server
certificate usage, and the normal Windows trust chain before invoking Compose.
It refuses missing, expired, or untrusted certificates with setup instructions.
It also validates and reloads Nginx, including when the stack is already running.
It never installs a CA or bypasses certificate validation automatically.

## Run and sign in

Open https://localhost:18443/login. HTTP on http://localhost:18088 redirects to
HTTPS. Both host ports bind to 127.0.0.1; internal services are not published.

The first successful setup/start creates `.env.windows` with a random server
master key and administrator password. Use its `SEED_ADMIN_EMAIL` and
`SEED_ADMIN_PASSWORD`. Keep this file private and retain its master key with
protected backups; losing it can prevent decryption. Existing settings are
preserved. To change ports, edit `EDGE_HTTP_PORT`, `EDGE_HTTPS_PORT`, and the
matching `SHARE_PUBLIC_BASE_URL` before starting.

```powershell
.\scripts\windows-stack.ps1 Status
.\scripts\windows-stack.ps1 Logs
.\scripts\windows-stack.ps1 Stop
.\scripts\windows-stack.ps1 Start
```

PostgreSQL metadata, encrypted vault blobs, and staged share payloads live in
separate named volumes under project `storage-boxes-windows`. Stop/Start retain
data. The old `make compose-down` command removes volumes; avoid it for this
persistent stack.

## Renewal and migration from an old archive

Never copy `.local-ca`, `fullchain.pem`, or `privkey.pem` from an old machine,
archive, or another deployment. Generate and explicitly trust a new local CA
on each computer. Existing app credentials, encryption master key, and data
volumes are independent of the HTTPS certificate; certificate replacement
must not regenerate them.

To renew a leaf using this computer's existing CA:

```powershell
.\scripts\setup-local-tls.ps1
.\scripts\setup-local-tls.ps1 -Activate
.\scripts\check-local-tls.ps1
.\scripts\windows-stack.ps1 Start
```

The final Start reloads the edge even when it is already running. Alternatively,
after validating the files, use `docker exec storage-boxes-windows-edge-1 nginx -t`
and `docker exec storage-boxes-windows-edge-1 nginx -s reload`. Reload is
asynchronous; retry validation after the new worker process has started.
Renew before expiry; the startup check warns within 30 days of leaf expiry.

## Verify HTTPS and troubleshoot Firefox

Use normal certificate validation after startup:

```powershell
(Invoke-WebRequest https://localhost:18443/login).StatusCode
```

Expected result: `200`, without `-SkipCertificateCheck`. Confirm the browser
certificate is for localhost and issued by this computer's CA, not an archived
self-signed `CN=localhost` certificate. A healthy container or a smoke test that
accepts self-signed certificates does not prove browser trust.

Firefox 120+ normally uses third-party roots installed in Windows. After
installing the CA, restart Firefox if necessary and confirm **Allow Firefox to
automatically trust third-party root certificates you install** is enabled.
See [Mozilla's documentation](https://support.mozilla.org/en-US/kb/automatically-trust-third-party-certificates).

If Firefox reports an expired *issuer*, inspect the issuer/root validity as
well as the leaf dates. An old trusted certificate can expire even when the
server leaf is still valid. Check the clock/timezone, and inspect the actual
certificate being served. Other expired localhost roots may belong to other
applications; investigate them before removing anything. Do not disable TLS
validation, remove HSTS, or change the clock to get past a certificate error.
HSTS may prevent adding an exception, so establish a valid trusted chain first.

## Checks and deployment scope

```powershell
.\scripts\windows-stack.ps1 Check
.\scripts\windows-stack.ps1 Smoke
```

Check runs release metadata checks plus the existing Go lint/build/unit/
integration/migration and TypeScript/Vitest checks inside disposable containers.
Smoke drives the running stack's login, encrypted storage, sharing, access
requests, and audit paths. It retains a timestamped sample box with password
`local-smoke-box-password`. Its isolated container accepts the edge's local
certificate; use the normal Windows HTTPS request above to verify browser trust.
The separate Compose acceptance harness removes its project's volumes; run it
only under an isolated project name. Playwright is also a separate suite.

Local mode still includes development OTP echo. For shared deployment, follow
[DEPLOYMENT.md](DEPLOYMENT.md): use production configuration, a CA trusted by
all clients for the actual hostname, SMTP for OTP, and validated recovery.
Do not distribute a development CA private key or install it on client machines
as a substitute for a properly planned shared TLS deployment.
