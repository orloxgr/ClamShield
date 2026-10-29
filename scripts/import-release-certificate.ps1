$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Release-key import is restricted to an ephemeral GitHub-hosted runner.' }
if (-not $env:RELEASE_PFX_BASE64 -or -not $env:RELEASE_PFX_PASSWORD) { throw 'Configure RELEASE_PFX_BASE64 and RELEASE_PFX_PASSWORD before a signed release build.' }
$certificatePath = Join-Path $env:RUNNER_TEMP 'clamshield-signing.pfx'
try {
    [System.IO.File]::WriteAllBytes($certificatePath, [Convert]::FromBase64String($env:RELEASE_PFX_BASE64))
    $password = ConvertTo-SecureString -String $env:RELEASE_PFX_PASSWORD -AsPlainText -Force
    Write-Output 'Importing the release signing certificate into the temporary runner.'
    $certificates = @(Import-PfxCertificate -FilePath $certificatePath -CertStoreLocation Cert:\CurrentUser\My -Password $password -Confirm:$false)
    $signers = @($certificates | Where-Object { $_.HasPrivateKey -and $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3' })
    if ($signers.Count -ne 1) { throw 'The release certificate must identify exactly one code-signing key.' }
    $signer = $signers[0]
    if ($signer.NotAfter -le (Get-Date) -or $signer.NotBefore -gt (Get-Date)) { throw 'Release signing certificate is not currently valid.' }
    "CLAMSHIELD_CODESIGN_SHA1=$($signer.Thumbprint)" | Out-File -LiteralPath $env:GITHUB_ENV -Append -Encoding utf8
    'CLAMSHIELD_REQUIRE_SIGNING=1' | Out-File -LiteralPath $env:GITHUB_ENV -Append -Encoding utf8
    # A local certificate is trusted only inside this ephemeral runner. This does
    # not make the published installer publicly trusted on consumer machines.
    if ($signer.Subject -eq $signer.Issuer) {
        # CurrentUser\Root can display an interactive trust dialog. The hosted
        # runner is an ephemeral administrator machine; its machine root store
        # supports noninteractive trust and is cleaned in the workflow's finally step.
        Write-Output 'Trusting the self-signed certificate on this ephemeral runner.'
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        try { $store.Open('ReadWrite'); $store.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signer.RawData)) } finally { $store.Close() }
    }
    Write-Output 'Release signing identity is ready.'
} finally {
    if (Test-Path -LiteralPath $certificatePath) { Remove-Item -LiteralPath $certificatePath -Force }
}
