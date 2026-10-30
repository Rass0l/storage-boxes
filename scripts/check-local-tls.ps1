#Requires -Version 7.2
[CmdletBinding()]
param([string]$TlsDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'deployments\compose\edge\tls'))

$ErrorActionPreference = 'Stop'
$certificatePath = Join-Path $TlsDirectory 'fullchain.pem'
$keyPath = Join-Path $TlsDirectory 'privkey.pem'
$help = 'Follow WINDOWS.md#trusted-local-https before starting the Windows stack.'
if (-not (Test-Path -LiteralPath $certificatePath) -or -not (Test-Path -LiteralPath $keyPath)) {
    throw "Local HTTPS certificate/key are missing. $help"
}
try { $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certificatePath, $keyPath) }
catch { throw "Local HTTPS certificate/key are malformed or do not match. $help" }
$chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $now = [DateTime]::UtcNow
    if ($leaf.NotBefore.ToUniversalTime() -gt $now -or $leaf.NotAfter.ToUniversalTime() -le $now) {
        throw "Local HTTPS certificate is expired or not yet valid. $help"
    }
    $san = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    $hasLocalhost = $false
    if ($san) {
        $reader = [System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]::new($san.RawData), [System.Formats.Asn1.AsnEncodingRules]::DER)
        $names = $reader.ReadSequence()
        while ($names.HasData) {
            $tag = $names.PeekTag()
            if ($tag.TagClass -eq [System.Formats.Asn1.TagClass]::ContextSpecific -and $tag.TagValue -eq 2) {
                if ($names.ReadCharacterString([System.Formats.Asn1.UniversalTagNumber]::IA5String, $tag) -eq 'localhost') { $hasLocalhost = $true }
            } else { $null = $names.ReadEncodedValue() }
        }
    }
    if (-not $hasLocalhost) { throw "Local HTTPS certificate does not include localhost in its DNS names. $help" }
    # mkcert local CAs have no revocation service. Validate validity, server
    # authentication usage and the normal Windows trust chain, without AIA fetch.
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.DisableCertificateDownloads = $true
    [void]$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    if (-not $chain.Build($leaf)) {
        $status = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ', '
        throw "Local HTTPS certificate chain is not trusted/valid ($status). $help"
    }
    if ($leaf.NotAfter.ToUniversalTime() -lt $now.AddDays(30)) { Write-Warning 'Local HTTPS certificate expires within 30 days. Renew it using the TLS setup guide.' }
    Write-Host "Local HTTPS: localhost / trusted Windows chain / expires $($leaf.NotAfter.ToString('yyyy-MM-dd')): PASS"
} finally { $chain.Dispose(); $leaf.Dispose() }
