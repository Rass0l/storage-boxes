#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$MkcertPath = 'mkcert',
    [switch]$Activate,
    [switch]$TrustCurrentUser
)

$ErrorActionPreference = 'Stop'
if ($TrustCurrentUser -and -not $Activate) { throw 'Use -Activate with -TrustCurrentUser when explicitly choosing to trust the prepared local CA.' }
if (-not (Get-Command $MkcertPath -ErrorAction SilentlyContinue)) { throw 'Install mkcert from its official project, or provide -MkcertPath.' }
$repoRoot = Split-Path -Parent $PSScriptRoot
$caRoot = Join-Path $repoRoot '.local-ca'
$tlsRoot = Join-Path $repoRoot 'deployments\compose\edge\tls'
$pendingCert = Join-Path $tlsRoot 'localhost.pending.pem'
$pendingKey = Join-Path $tlsRoot 'localhost-key.pending.pem'
$previousCARoot = $env:CAROOT
New-Item -ItemType Directory -Path $caRoot, $tlsRoot -Force | Out-Null
# A local CA key can issue certificates trusted by this user. Restrict its
# directory before generating any private material; it is never mounted in edge.
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $caRoot /inheritance:r /grant:r ('*' + $sid + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict local CA directory permissions.' }
try {
    $env:CAROOT = $caRoot
    if (-not $Activate) {
        & $MkcertPath -cert-file $pendingCert -key-file $pendingKey localhost 127.0.0.1 ::1
        if ($LASTEXITCODE -ne 0) { throw 'Local certificate generation failed.' }
    }
    # Reading both files checks that the private key matches the certificate.
    $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($pendingCert, $pendingKey)
    $caPath = Join-Path $caRoot 'rootCA.pem'
    $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($caPath))
    try {
        if ($leaf.NotAfter -le (Get-Date) -or $leaf.NotBefore -gt (Get-Date)) { throw 'Prepared certificate is outside its validity period.' }
        Write-Host "Local CA: $($ca.Subject)"
        Write-Host "CA thumbprint: $($ca.Thumbprint)"
        Write-Host "Leaf validity: $($leaf.NotBefore.ToString('yyyy-MM-dd')) to $($leaf.NotAfter.ToString('yyyy-MM-dd'))"
        if ($TrustCurrentUser) {
            # This is a persistent user trust change. Run only after choosing
            # to trust this locally generated CA; never import an archived CA.
            Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
            Write-Host 'Installed this CA in the current Windows user root store.'
        }
        if ($Activate) {
            Copy-Item -LiteralPath $pendingCert -Destination (Join-Path $tlsRoot 'fullchain.pem') -Force
            Copy-Item -LiteralPath $pendingKey -Destination (Join-Path $tlsRoot 'privkey.pem') -Force
            Write-Host 'Activated the prepared certificate files. Reload the Compose edge to serve them.'
        } else {
            Write-Host 'Prepared only. No browser/Windows trust settings or active server certificate were changed.'
        }
    } finally { $leaf.Dispose(); $ca.Dispose() }
} finally {
    if ($null -eq $previousCARoot) { Remove-Item Env:\CAROOT -ErrorAction SilentlyContinue }
    else { $env:CAROOT = $previousCARoot }
}
