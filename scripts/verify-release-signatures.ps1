param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
if (-not $env:CLAMSHIELD_CODESIGN_SHA1) { throw 'An explicit release signer thumbprint is required.' }
$version = (Get-Content -LiteralPath package.json -Raw | ConvertFrom-Json).version
$targets = @("ClamShield-Setup-$version.exe", 'win-unpacked/ClamShield.exe', 'win-unpacked/shell/ClamShieldShellExt.dll')
foreach ($target in $targets) {
    $file = Join-Path $Directory $target
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $env:CLAMSHIELD_CODESIGN_SHA1) { throw "Release signature verification failed: $target" }
    Write-Output "Verified release signature: $target"
}
