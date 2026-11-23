[CmdletBinding()]
param(
  [string]$ConfigPath = "$(Join-Path $PSScriptRoot '..\..\config\customer.windows.example.yaml')",
  [string]$TransactionScratchPath = '',
  [switch]$AllowSharedSandboxUpgrade,
  [UInt64]$MinimumFreeBytes = 3GB
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HONGAI-Windows.Common.ps1')

Assert-HongAiWindows
Assert-HongAiAdministrator
$MachineMutationLock = Enter-HongAiMachineMutationLock

try {
$ProjectRoot = Assert-HongAiDataDrivePath -Path (Get-HongAiProjectRoot) -Label 'Offline installation root'
$ResolvedConfig = Assert-HongAiDataDrivePath -Path (Resolve-Path -LiteralPath $ConfigPath).Path -Label 'Customer configuration'
$ResolvedTransactionScratch = if ([string]::IsNullOrWhiteSpace($TransactionScratchPath)) {
  ''
} else {
  Assert-HongAiDataDrivePath -Path (Resolve-Path -LiteralPath $TransactionScratchPath).Path -Label 'Protected transaction scratch directory'
}
$Payload = Get-HongAiOfflinePayload -ProjectRoot $ProjectRoot -VerifyPortableManifest
$AvailableBytes = Assert-HongAiFreeSpace -Path $ProjectRoot -MinimumFreeBytes $MinimumFreeBytes
$StatePath = Get-HongAiInstallStatePath -ProjectRoot $ProjectRoot

if (Test-Path -LiteralPath $StatePath) {
  throw "An installation state already exists at $StatePath. Run the uninstaller/recovery flow before retrying; doctor is only for a completed installation."
}

Invoke-HongAiNodeCommand `
  -NodePath $Payload.NodePath `
  -ScriptPath $Payload.CliPath `
  -Arguments @('validate', '--config', $ResolvedConfig) `
  -FailureMessage 'Customer configuration validation failed'

$SandboxStatus = Get-HongAiSandboxStatus -SrtWinPath $Payload.SrtWinPath
$SandboxPreexisting = Test-HongAiSandboxPresent -Status $SandboxStatus
$InstallingState = [ordered]@{
  schemaVersion = 1
  product = 'HONG AI Edge Cage'
  version = [string](Get-Content -LiteralPath $Payload.PackageJsonPath -Raw | ConvertFrom-Json).version
  status = 'INSTALLING'
  startedAt = [DateTime]::UtcNow.ToString('o')
  node = [ordered]@{
    source = $Payload.NodeSource
    version = $Payload.NodeVersion
    architecture = $Payload.Architecture
  }
  configSha256 = Get-HongAiFileSha256 -Path $ResolvedConfig
  deliveryManifestSha256 = Get-HongAiFileSha256 -Path (Join-Path $ProjectRoot 'HONGAI-DELIVERY.json')
  payloadManifestSha256 = Get-HongAiFileSha256 -Path (Join-Path $ProjectRoot 'HONGAI-PAYLOAD.json')
  sandboxPreexisting = $SandboxPreexisting
  sandboxProvisionedByThisInstall = $false
  sharedSandboxUpgradeRequested = [bool]$AllowSharedSandboxUpgrade
  availableBytesAtInstall = $AvailableBytes
}

# Persist ownership intent before the first machine-wide SRT/WFP mutation. If
# power is lost, the uninstaller can distinguish an interrupted fresh install
# from a pre-existing shared sandbox and recover without guessing.
Write-HongAiJsonAtomic -Path $StatePath -Value $InstallingState -ScratchDirectory $ResolvedTransactionScratch
$ProvisionAttempted = $false
$ProvisionedByThisInstall = $false

try {
  if (-not $SandboxPreexisting) {
    Write-Host 'Provisioning the dedicated Windows sandbox account and WFP egress fence...'
    $ProvisionAttempted = $true
    Invoke-HongAiNodeCommand `
      -NodePath $Payload.NodePath `
      -ScriptPath $Payload.SrtCliPath `
      -Arguments @('windows-install', '--skip-profile-grant') `
      -FailureMessage 'Sandbox Runtime Windows provisioning failed'
    $ProvisionedByThisInstall = $true
  } elseif ($AllowSharedSandboxUpgrade) {
    Write-Host 'Upgrading the pre-existing shared Sandbox Runtime installation by explicit request...' -ForegroundColor Yellow
    $ProvisionAttempted = $true
    Invoke-HongAiNodeCommand `
      -NodePath $Payload.NodePath `
      -ScriptPath $Payload.SrtCliPath `
      -Arguments @('windows-install', '--skip-profile-grant') `
      -FailureMessage 'Pre-existing Sandbox Runtime upgrade failed'
  } else {
    Write-Host 'A machine-wide Sandbox Runtime installation already exists; preserving it and verifying compatibility.' -ForegroundColor Yellow
  }

  if ($SandboxPreexisting -and -not $AllowSharedSandboxUpgrade) {
    $DoctorFailure = 'The pre-existing Sandbox Runtime is incompatible or the fail-closed doctor failed. Nothing was changed; use -AllowSharedSandboxUpgrade only after confirming no other application depends on it'
  } else {
    $DoctorFailure = 'Offline installation completed provisioning, but the fail-closed doctor did not pass'
  }
  Invoke-HongAiNodeCommand `
    -NodePath $Payload.NodePath `
    -ScriptPath $Payload.CliPath `
    -Arguments @('doctor', '--config', $ResolvedConfig) `
    -FailureMessage $DoctorFailure

  $InstallingState.status = 'INSTALLED'
  $InstallingState.installedAt = [DateTime]::UtcNow.ToString('o')
  $InstallingState.sandboxProvisionedByThisInstall = $ProvisionedByThisInstall
  Write-HongAiJsonAtomic -Path $StatePath -Value $InstallingState -ScratchDirectory $ResolvedTransactionScratch
  Write-Host 'HONG AI Edge Cage offline installation and fail-closed doctor completed.' -ForegroundColor Green
} catch {
  $PrimaryError = $_
  if ($ProvisionAttempted -and -not $SandboxPreexisting) {
    Write-Warning 'Installation failed after fresh machine provisioning. Rolling back the sandbox account and WFP filters...'
    try {
      Invoke-HongAiNodeCommand `
        -NodePath $Payload.NodePath `
        -ScriptPath $Payload.SrtCliPath `
        -Arguments @('windows-uninstall') `
        -FailureMessage 'Automatic Sandbox Runtime rollback failed'
      $StatusAfterRollback = Get-HongAiSandboxStatus -SrtWinPath $Payload.SrtWinPath
      if (Test-HongAiSandboxPresent -Status $StatusAfterRollback) {
        throw 'Automatic rollback returned success, but sandbox account, credential, group, or WFP state remains present.'
      }
      Remove-Item -LiteralPath $StatePath -Force
    } catch {
      throw "Installation failed: $($PrimaryError.Exception.Message) Automatic rollback also failed: $($_.Exception.Message)"
    }
  } elseif ($ProvisionAttempted -and $SandboxPreexisting) {
    Write-Warning 'The explicitly requested shared Sandbox Runtime upgrade may have changed machine-wide state. It was not removed automatically because another application may own it.'
  }
  throw $PrimaryError
}
} finally {
  Exit-HongAiMachineMutationLock -Mutex $MachineMutationLock
}
