[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$SrtCliPath = Join-Path $ProjectRoot 'node_modules\@anthropic-ai\sandbox-runtime\dist\cli.js'

if (-not (Test-Path -LiteralPath $SrtCliPath)) {
  throw 'Sandbox Runtime is not present in this installation.'
}

& node $SrtCliPath windows-uninstall
if ($LASTEXITCODE -ne 0) {
  throw 'Windows sandbox removal failed.'
}
Write-Host 'Windows sandbox account and WFP filters removed. Customer state was preserved.' -ForegroundColor Green
