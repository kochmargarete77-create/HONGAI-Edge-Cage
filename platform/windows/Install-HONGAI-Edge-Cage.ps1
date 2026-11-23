[CmdletBinding()]
param(
  [string]$ConfigPath = "$(Join-Path $PSScriptRoot '..\..\config\customer.windows.example.yaml')"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  throw 'This installer is for Windows only.'
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ResolvedConfig = (Resolve-Path $ConfigPath).Path
$CliPath = Join-Path $ProjectRoot 'dist\src\cli.js'
$SrtCliPath = Join-Path $ProjectRoot 'node_modules\@anthropic-ai\sandbox-runtime\dist\cli.js'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'Node.js 24 or newer is required for this source installer.'
}
$NodeMajor = [int](& node -p "Number(process.versions.node.split('.')[0])")
if ($NodeMajor -lt 24) {
  throw "Node.js 24 or newer is required; detected $(& node --version)."
}

$env:npm_config_cache = Join-Path $ProjectRoot '.npm-cache'
$env:TEMP = Join-Path $ProjectRoot '.tmp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:npm_config_cache, $env:TEMP | Out-Null

Push-Location $ProjectRoot
try {
  & npm ci --fund=false --audit=false
  if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
  & npm run build
  if ($LASTEXITCODE -ne 0) { throw 'TypeScript build failed.' }
  & node $CliPath validate --config $ResolvedConfig
  if ($LASTEXITCODE -ne 0) { throw 'Customer configuration validation failed.' }

  Write-Host 'Installing the dedicated Windows sandbox account and WFP egress fence...'
  & node $SrtCliPath windows-install --skip-profile-grant
  if ($LASTEXITCODE -ne 0) { throw 'Sandbox Runtime Windows provisioning failed.' }

  & node $CliPath doctor --config $ResolvedConfig
  if ($LASTEXITCODE -ne 0) {
    throw 'Installation completed, but fail-closed network preflight did not pass.'
  }
  Write-Host 'HONG AI Edge Cage installation and preflight completed.' -ForegroundColor Green
} finally {
  Pop-Location
}
