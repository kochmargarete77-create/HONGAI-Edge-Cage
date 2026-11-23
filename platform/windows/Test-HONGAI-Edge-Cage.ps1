[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HONGAI-Windows.Common.ps1')

Assert-HongAiWindows
$ProjectRoot = Assert-HongAiDataDrivePath -Path (Get-HongAiProjectRoot) -Label 'Offline installation root'
$ResolvedConfig = Assert-HongAiDataDrivePath -Path (Resolve-Path -LiteralPath $ConfigPath).Path -Label 'Customer configuration'
$Payload = Get-HongAiOfflinePayload -ProjectRoot $ProjectRoot -VerifyPortableManifest -AllowInstalledState
$State = Read-HongAiInstalledState -ProjectRoot $ProjectRoot
Assert-HongAiInstalledConfig -State $State -ConfigPath $ResolvedConfig

Invoke-HongAiNodeCommand `
  -NodePath $Payload.NodePath `
  -ScriptPath $Payload.CliPath `
  -Arguments @('doctor', '--config', $ResolvedConfig) `
  -FailureMessage 'HONG AI Edge Cage doctor failed'

Write-Host 'HONG AI Edge Cage doctor passed.' -ForegroundColor Green
