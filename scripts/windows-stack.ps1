#Requires -Version 7.2
[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status', 'Logs', 'Config', 'Check', 'Smoke')]
    [string]$Action = 'Start',
    [ValidatePattern('^[a-z0-9][a-z0-9_-]*$')]
    [string]$ProjectName = 'storage-boxes-windows'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeDir = Join-Path $repoRoot 'deployments\compose'
$envPath = Join-Path $repoRoot '.env.windows'

function New-HexSecret([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Install Docker Desktop with the Linux containers engine and Docker Compose.'
}

if ($Action -eq 'Start') { & (Join-Path $PSScriptRoot 'check-local-tls.ps1') }

if (-not (Test-Path -LiteralPath $envPath)) {
    if ($Action -ne 'Start') { throw 'Run windows-stack.ps1 Start once to initialize local settings.' }
    $settings = Get-Content -LiteralPath (Join-Path $repoRoot '.env.example') -Raw
    $settings = $settings -replace '(?m)^SERVER_MASTER_KEY=.*$', ('SERVER_MASTER_KEY=' + (New-HexSecret 32))
    $settings = $settings -replace '(?m)^SEED_ADMIN_PASSWORD=.*$', ('SEED_ADMIN_PASSWORD=' + (New-HexSecret 16))
    $settings = $settings -replace '(?m)^EDGE_HTTPS_PORT=.*$', 'EDGE_HTTPS_PORT=18443'
    $settings = $settings -replace '(?m)^EDGE_HTTP_PORT=.*$', 'EDGE_HTTP_PORT=18088'
    $settings = $settings -replace '(?m)^SHARE_PUBLIC_BASE_URL=.*$', 'SHARE_PUBLIC_BASE_URL=https://localhost:18443'
    [IO.File]::WriteAllText($envPath, $settings, (New-Object Text.UTF8Encoding $false))
    Write-Host 'Created .env.windows with a random master key and admin password. Keep this file with your backups.'
}

$composeArgs = @('compose', '--project-name', $ProjectName, '--env-file', $envPath,
    '--project-directory', $composeDir,
    '-f', (Join-Path $composeDir 'docker-compose.yml'),
    '-f', (Join-Path $composeDir 'docker-compose.windows.yml'))

switch ($Action) {
    'Start'  {
        & docker @composeArgs up -d --build --wait --wait-timeout 180
        if ($LASTEXITCODE -ne 0) { throw 'Docker Compose Start failed.' }
        # Bind-mounted certificate changes do not recreate an existing edge.
        # Explicitly reload so renewal also works when the stack is already up.
        & docker @composeArgs exec -T edge nginx -t
        if ($LASTEXITCODE -ne 0) { throw 'Edge TLS configuration validation failed.' }
        & docker @composeArgs exec -T edge nginx -s reload
    }
    # Stop preserves containers and named volumes. No destructive reset action.
    'Stop'   { & docker @composeArgs stop }
    'Status' { & docker @composeArgs ps -a }
    'Logs'   { & docker @composeArgs logs --tail 100 }
    # Quiet validation avoids printing resolved secrets.
    'Config' { & docker @composeArgs config --quiet }
    'Smoke' { & docker @composeArgs --profile checks run --rm --no-deps smoke-check }
    'Check' {
        & (Join-Path $PSScriptRoot 'check-release.ps1')
        & docker @composeArgs --profile checks run --rm --build --no-deps go-check
        if ($LASTEXITCODE -ne 0) { throw 'Backend checks failed.' }
        & docker @composeArgs --profile checks run --rm --build --no-deps web-check
    }
}
if ($LASTEXITCODE -ne 0) { throw "Docker Compose $Action failed (exit $LASTEXITCODE)." }

if ($Action -eq 'Start') {
    $httpsPort = (Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^EDGE_HTTPS_PORT=' }) -replace '^EDGE_HTTPS_PORT=', ''
    Write-Host "Open https://localhost:$httpsPort/login (validated local HTTPS certificate)."
    Write-Host "Admin: admin@example.local. Password is SEED_ADMIN_PASSWORD in $envPath"
}
