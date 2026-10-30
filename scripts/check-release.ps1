#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'VERSION must contain a three-part application version.' }
$package = Get-Content -LiteralPath (Join-Path $repoRoot 'web/package.json') -Raw | ConvertFrom-Json -AsHashtable
$lock = Get-Content -LiteralPath (Join-Path $repoRoot 'web/package-lock.json') -Raw | ConvertFrom-Json -AsHashtable
if ($package.version -ne $version -or $lock.version -ne $version -or $lock.packages[''].version -ne $version) {
    throw 'VERSION, package.json, and root lockfile versions disagree.'
}
if ($package.license -ne 'Apache-2.0' -or $lock.packages[''].license -ne 'Apache-2.0') { throw 'Package license metadata must be Apache-2.0.' }
$spec = Get-Content -LiteralPath (Join-Path $repoRoot 'api/openapi/openapi.yaml') -Raw
if ($spec -notmatch ('(?m)^  version: ' + [regex]::Escape($version) + '\r?$')) { throw 'OpenAPI info.version differs from VERSION.' }
foreach ($doc in @('README.md', 'WINDOWS.md', 'CONTRIBUTING.md', 'DEPLOYMENT.md', 'docs/project-status.md')) {
    if (-not ([IO.File]::ReadAllText((Join-Path $repoRoot $doc))).Contains($version)) { throw "Current version missing from $doc" }
}
foreach ($service in @('api', 'worker', 'share-gateway', 'migrate', 'frontend')) {
    $dockerfile = [IO.File]::ReadAllText((Join-Path $repoRoot "deployments/docker/$service.Dockerfile"))
    if (-not $dockerfile.Contains('org.opencontainers.image.version="' + $version + '"')) { throw "Image version differs for $service" }
}
foreach ($required in @('NOTICE', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md')) {
    if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText((Join-Path $repoRoot $required)))) { throw "Missing release file: $required" }
}
$text = [IO.File]::ReadAllText((Join-Path $repoRoot 'LICENSE')).Replace("`r`n", "`n")
$hasher = [Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-', '').ToLowerInvariant() }
finally { $hasher.Dispose() }
if ($hash -ne 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30') { throw 'LICENSE differs from the canonical Apache 2.0 text.' }
Write-Host "Release metadata: $version / Apache-2.0 / notices: PASS"
