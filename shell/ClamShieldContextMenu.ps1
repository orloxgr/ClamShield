param(
  [Parameter(Mandatory = $true)]
  [string]$Action,

  [Parameter(Mandatory = $true)]
  [string]$Target,

  [Parameter(Mandatory = $false)]
  [string]$FallbackExe = ""
)

$ErrorActionPreference = "Stop"

function Invoke-ClamShieldBridge {
  $bridgePath = Join-Path $env:ProgramData "ClamShield\context-menu-bridge.json"
  if (-not (Test-Path -LiteralPath $bridgePath)) {
    throw "ClamShield context menu bridge is not available."
  }

  $bridge = Get-Content -LiteralPath $bridgePath -Raw | ConvertFrom-Json
  if (-not $bridge.port -or -not $bridge.token) {
    throw "ClamShield context menu bridge data is incomplete."
  }

  $payload = @{
    action = $Action
    targets = @($Target)
  } | ConvertTo-Json -Compress

  Invoke-RestMethod `
    -Method Post `
    -Uri ("http://127.0.0.1:{0}/context-menu" -f [int]$bridge.port) `
    -Headers @{ "X-ClamShield-Bridge" = [string]$bridge.token } `
    -ContentType "application/json" `
    -Body $payload `
    -TimeoutSec 4 | Out-Null
}

try {
  Invoke-ClamShieldBridge
} catch {
  if ($FallbackExe -and (Test-Path -LiteralPath $FallbackExe)) {
    Start-Process -FilePath $FallbackExe -ArgumentList @("--context-menu-legacy", $Action, $Target) | Out-Null
  }
}
