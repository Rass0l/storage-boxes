#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Destination,
    [string[]]$SecretEnvPath = @()
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
& (Join-Path $PSScriptRoot 'check-release.ps1')
if (-not $Destination) {
    $Destination = Join-Path (Split-Path -Parent $repoRoot) ('publish\source-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$Destination = [IO.Path]::GetFullPath($Destination)
if ($Destination.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or $Destination -eq $repoRoot) {
    throw 'Export outside the working project so local runtime files cannot enter the snapshot.'
}
if (Test-Path -LiteralPath $Destination) { throw 'Destination exists; choose a new directory.' }
foreach ($command in @('git', 'docker')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command is required." }
}

# Ask Git which files would be included. Before the first git init, use temporary
# metadata while honoring this project's .gitignore. No commit or remote is made.
$temporaryGit = $null
try {
    if (Test-Path -LiteralPath (Join-Path $repoRoot '.git')) {
        $gitDir = & git -C $repoRoot rev-parse --absolute-git-dir
        if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the project Git directory.' }
    } else {
        $temporaryGit = Join-Path ([IO.Path]::GetTempPath()) ('storage-boxes-export-' + [Guid]::NewGuid().ToString('N'))
        & git init --bare --quiet $temporaryGit
        if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize temporary Git metadata.' }
        $gitDir = $temporaryGit
    }
    $files = @(& git -c core.quotePath=false --git-dir $gitDir --work-tree $repoRoot ls-files --cached --others --exclude-standard) | Sort-Object -Unique
    if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) { throw 'Cannot enumerate repository candidates.' }

    foreach ($relative in $files) {
        $name = [IO.Path]::GetFileName($relative)
        $isExample = $name -in @('.env.example', '.env.test.example')
        if ((($name -eq '.env' -or $name.StartsWith('.env.', [StringComparison]::OrdinalIgnoreCase) -or $name.EndsWith('.env', [StringComparison]::OrdinalIgnoreCase)) -and -not $isExample) -or
            $relative -match '^env(\.|$)' -or
            $relative -match '(^|/)(backups|\.local-ca|\.box-storage[^/]*|\.share-stage[^/]*|tls)/' -or
            $relative -match '(?i)\.(pem|key|p12|pfx|dump|exe|dll|tar|tgz|zip|log)(\.gz)?$' -or
            $relative -in @('env', 'worker', 'migrate', 'share-gateway', 'REVIVAL-STATUS.md')) {
            throw "Non-source file in the Git candidate: $relative. Untrack it before publishing."
        }
        $source = [IO.Path]::GetFullPath((Join-Path $repoRoot $relative))
        if (-not $source.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Candidate path escaped project root.' }
        $item = Get-Item -LiteralPath $source
        $ancestor = $item
        while ($ancestor -and $ancestor.FullName -ne $repoRoot) {
            if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Review linked path before export: $relative" }
            $ancestor = if ($ancestor.PSIsContainer) { $ancestor.Parent } else { $ancestor.Directory }
        }
    }

    foreach ($required in @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'VERSION', 'README.md', 'SECURITY.md')) {
        if ($required -notin $files) { throw "Required release file is missing from the Git candidate: $required" }
    }
    $licenseText = [IO.File]::ReadAllText((Join-Path $repoRoot 'LICENSE')).Replace("`r`n", "`n")
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $licenseHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($licenseText)))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
    if ($licenseHash -ne 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30') {
        throw 'LICENSE differs from the canonical Apache 2.0 text. Review before publishing.'
    }

    New-Item -ItemType Directory -Path $Destination | Out-Null
    foreach ($relative in $files) {
        $target = Join-Path $Destination $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $repoRoot $relative) -Destination $target
    }
} finally {
    if ($temporaryGit -and (Test-Path -LiteralPath $temporaryGit)) {
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $resolvedGit = [IO.Path]::GetFullPath($temporaryGit)
        if (-not $resolvedGit.StartsWith($temporaryRoot + 'storage-boxes-export-', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Unexpected temporary Git path; refusing cleanup.'
        }
        Remove-Item -LiteralPath $resolvedGit -Recurse -Force
    }
}

# Also match real local credentials exactly, without printing them or passing
# them to Docker. Values copied from public example files are test defaults.
$exampleValues = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($example in @('.env.example', '.env.test.example')) {
    foreach ($line in Get-Content -LiteralPath (Join-Path $repoRoot $example)) {
        if ($line -match '^\s*[^#=]+=(.+)$') { [void]$exampleValues.Add($Matches[1].Trim()) }
    }
}
$secrets = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$localEnv = @(Get-ChildItem -LiteralPath $repoRoot -Force -File | Where-Object {
    ($_.Name -eq '.env' -or $_.Name.StartsWith('.env.', [StringComparison]::OrdinalIgnoreCase) -or $_.Name.EndsWith('.env', [StringComparison]::OrdinalIgnoreCase)) -and $_.Name -notin @('.env.example', '.env.test.example')
} | ForEach-Object FullName) + $SecretEnvPath
foreach ($envFile in $localEnv) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim().Trim('"').Trim("'")
            if ($key -match '(?i)TOKEN|PASSWORD|SECRET|MASTER_KEY|PRIVATE_KEY' -and
                $value.Length -gt 0 -and -not $exampleValues.Contains($value)) { [void]$secrets.Add($value) }
        }
    }
}
foreach ($relative in $files) {
    $content = [IO.File]::ReadAllText((Join-Path $Destination $relative))
    foreach ($secret in $secrets) {
        if ($content.Contains($secret)) { throw "A local credential was found in $relative. Snapshot is NOT ready to publish." }
    }
}

# Pinned official Gitleaks v8.30.1 image. The scan has no network access and
# mounts only the filtered snapshot, read-only. Findings are redacted.
$scanner = 'ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
& docker run --rm --network none --mount "type=bind,source=$Destination,target=/repo,readonly" $scanner dir --redact --no-banner /repo
if ($LASTEXITCODE -ne 0) { throw 'Secret scan failed. This snapshot is NOT ready to publish.' }
Write-Host "PASS: $($files.Count) source files exported; local credential matching and Gitleaks passed."
Write-Host "Snapshot: $Destination"
Write-Host 'No repository was created, committed, or pushed.'
