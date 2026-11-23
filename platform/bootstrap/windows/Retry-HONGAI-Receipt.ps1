[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$PendingReceipt
)

$ErrorActionPreference = 'Stop'
Remove-Item Env:NODE_OPTIONS -ErrorAction SilentlyContinue
Remove-Item Env:NODE_PATH -ErrorAction SilentlyContinue
Remove-Item Env:NPM_CONFIG_USERCONFIG -ErrorAction SilentlyContinue
Remove-Item Env:npm_config_userconfig -ErrorAction SilentlyContinue
$bootstrapRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$node = Join-Path $bootstrapRoot 'runtime\node.exe'
$runner = Join-Path $bootstrapRoot 'bootstrap-runner.mjs'
$arguments = @($runner, 'receipt')
if ($PendingReceipt) { $arguments += $PendingReceipt }

if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Bundled Node runtime is missing: $node" }
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw "Bootstrap runner is missing: $runner" }

& $node @arguments
exit $LASTEXITCODE
