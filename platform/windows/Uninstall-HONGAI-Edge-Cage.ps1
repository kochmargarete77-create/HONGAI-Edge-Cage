[CmdletBinding()]
param(
  [switch]$RemoveSharedSandbox,
  [switch]$SuppressInterruptedCompletionRecord
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HONGAI-Windows.Common.ps1')

Assert-HongAiWindows
Assert-HongAiAdministrator
$MachineMutationLock = Enter-HongAiMachineMutationLock

try {
$ProjectRoot = Assert-HongAiDataDrivePath -Path (Get-HongAiProjectRoot) -Label 'Offline installation root'
$Payload = Get-HongAiOfflinePayload -ProjectRoot $ProjectRoot -VerifyPortableManifest -AllowInstalledState
$StatePath = Get-HongAiInstallStatePath -ProjectRoot $ProjectRoot
$State = $null
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
  try {
    $State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
  } catch {
    throw "Installation ownership state is malformed; refusing machine-wide removal: $($_.Exception.Message)"
  }
  if (
    $State.schemaVersion -ne 1 -or
    $State.product -ne 'HONG AI Edge Cage' -or
    [string]$State.status -notin @('INSTALLED', 'INSTALLING')
  ) {
    throw 'Installation ownership state is invalid; refusing machine-wide removal.'
  }
  if ($State.PSObject.Properties.Name -notcontains 'sandboxPreexisting' -or $State.sandboxPreexisting -isnot [bool]) {
    throw 'Installation ownership state does not contain a trustworthy sandboxPreexisting flag; refusing machine-wide removal.'
  }
}

if ($null -eq $State -and -not $RemoveSharedSandbox) {
  throw "Installation ownership state is missing at $StatePath. Refusing to remove a potentially shared sandbox; use -RemoveSharedSandbox only after confirming no other application depends on it."
}

$InterruptedInstall = $null -ne $State -and [string]$State.status -eq 'INSTALLING'
$SuppressCompletionRecord = [bool]$SuppressInterruptedCompletionRecord
if ($SuppressCompletionRecord -and -not $InterruptedInstall) {
  throw '-SuppressInterruptedCompletionRecord is reserved for delivery-controller recovery of a verified INSTALLING journal.'
}
$OwnedSandbox = $false
if ($null -ne $State -and [string]$State.status -eq 'INSTALLED') {
  if (
    $State.PSObject.Properties.Name -notcontains 'sandboxProvisionedByThisInstall' -or
    $State.sandboxProvisionedByThisInstall -isnot [bool]
  ) {
    throw 'Installed ownership state does not contain a trustworthy sandbox ownership flag; refusing machine-wide removal.'
  }
  $OwnedSandbox = [bool]$State.sandboxProvisionedByThisInstall
}

if ($InterruptedInstall) {
  # INSTALLING means the process may have died anywhere around provisioning.
  # A false pre-existing flag proves this transaction started from an empty
  # machine state; true means the shared installation must never be removed.
  $RemoveSandbox = -not [bool]$State.sandboxPreexisting
  if ($State.sandboxPreexisting -and $RemoveSharedSandbox) {
    Write-Warning '-RemoveSharedSandbox is ignored for interrupted installs because the ownership journal proves the sandbox pre-existed this transaction.'
  }
} else {
  $RemoveSandbox = $OwnedSandbox -or [bool]$RemoveSharedSandbox
}

if ($RemoveSandbox) {
  $StatusBeforeRemoval = Get-HongAiSandboxStatus -SrtWinPath $Payload.SrtWinPath
  if (Test-HongAiSandboxPresent -Status $StatusBeforeRemoval) {
    Invoke-HongAiNodeCommand `
      -NodePath $Payload.NodePath `
      -ScriptPath $Payload.SrtCliPath `
      -Arguments @('windows-uninstall') `
      -FailureMessage 'Windows sandbox removal failed'
  } else {
    Write-Host 'No sandbox account or WFP state remains from the interrupted installation.' -ForegroundColor Yellow
  }

  $StatusAfterRemoval = Get-HongAiSandboxStatus -SrtWinPath $Payload.SrtWinPath
  if (Test-HongAiSandboxPresent -Status $StatusAfterRemoval) {
    throw 'Sandbox Runtime uninstall returned success, but the account, credential, group, or WFP filter state is still present.'
  }
  $FinalStatus = 'UNINSTALLED'
  Write-Host 'Windows sandbox account, grants and WFP filters were removed.' -ForegroundColor Green
} else {
  $FinalStatus = 'APPLICATION_DETACHED'
  Write-Host 'The pre-existing shared Sandbox Runtime installation was preserved.' -ForegroundColor Yellow
}

$UpdatedState = [ordered]@{
  schemaVersion = 1
  product = 'HONG AI Edge Cage'
  version = if ($null -ne $State) { [string]$State.version } else { 'unknown' }
  status = $FinalStatus
  uninstalledAt = [DateTime]::UtcNow.ToString('o')
  previousStatus = if ($null -ne $State) { [string]$State.status } else { 'MISSING' }
  interruptedRecovery = $InterruptedInstall
  sandboxRemoved = $RemoveSandbox
  sharedSandboxRemovalRequested = [bool]$RemoveSharedSandbox
}
$CompletionPath = "$StatePath.completed.$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))"
if (-not $SuppressCompletionRecord) {
  Write-HongAiJsonAtomic -Path $CompletionPath -Value $UpdatedState
}
if (Test-Path -LiteralPath $StatePath) {
  Remove-Item -LiteralPath $StatePath -Force
}
Write-Host 'Customer workspace and isolated agent state were preserved.' -ForegroundColor Green
} finally {
  Exit-HongAiMachineMutationLock -Mutex $MachineMutationLock
}
