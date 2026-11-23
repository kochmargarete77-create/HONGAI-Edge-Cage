[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ConfigPath,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ClaudeArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$CliPath = Join-Path $ProjectRoot 'dist\src\cli.js'
$ResolvedConfig = (Resolve-Path $ConfigPath).Path

& node $CliPath launch --config $ResolvedConfig -- @ClaudeArguments
exit $LASTEXITCODE
