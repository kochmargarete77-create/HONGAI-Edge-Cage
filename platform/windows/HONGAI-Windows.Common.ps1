Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Customer shells are not trusted execution environments. Prevent globally set
# Node/npm loader hooks from injecting code into the bundled offline runtime.
foreach ($HongAiUnsafeEnvironmentName in @(
  'NODE_OPTIONS',
  'NODE_PATH',
  'NPM_CONFIG_USERCONFIG',
  'npm_config_userconfig'
)) {
  Remove-Item -LiteralPath "Env:$HongAiUnsafeEnvironmentName" -ErrorAction SilentlyContinue
}
Remove-Variable HongAiUnsafeEnvironmentName -ErrorAction SilentlyContinue

function Assert-HongAiWindows {
  if ($env:OS -ne 'Windows_NT') {
    throw 'This command is supported only on Windows.'
  }
}

function Assert-HongAiAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this command from an elevated Windows PowerShell terminal (Run as administrator).'
  }
}

function Enter-HongAiMachineMutationLock {
  $createdNew = $false
  $mutex = [Threading.Mutex]::new($false, 'Global\HONGAI-Edge-Cage-SRT-WFP-v1', [ref]$createdNew)
  try {
    try {
      $acquired = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
      $acquired = $true
    }
    if (-not $acquired) {
      throw 'Another HONG AI Edge Cage installation, recovery, or uninstall is already changing machine-wide SRT/WFP state.'
    }
    return $mutex
  } catch {
    $mutex.Dispose()
    throw
  }
}

function Exit-HongAiMachineMutationLock {
  param(
    [Parameter(Mandatory = $true)]
    [Threading.Mutex]$Mutex
  )
  try {
    $Mutex.ReleaseMutex()
  } finally {
    $Mutex.Dispose()
  }
}

function Get-HongAiProjectRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Assert-HongAiDataDrivePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$Label = 'Path'
  )

  $fullPath = [IO.Path]::GetFullPath($Path)
  if ($fullPath -notmatch '^[DE]:\\') {
    throw "$Label must be located on the D: or E: data drive; refusing project-generated state on the system drive."
  }
  $candidate = $fullPath
  while ($true) {
    if (Test-Path -LiteralPath $candidate) {
      $item = Get-Item -LiteralPath $candidate -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label contains a junction, mount point, or symbolic-link ancestor at $candidate; reparse-point delivery paths are unsupported."
      }
    }
    $parent = [IO.Path]::GetDirectoryName($candidate.TrimEnd('\\'))
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) { break }
    $candidate = $parent
  }
  return $fullPath
}

function Get-HongAiWindowsArchitecture {
  $architecture = $env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($architecture)) {
    $architecture = $env:PROCESSOR_ARCHITECTURE
  }
  switch -Regex ($architecture) {
    '^(AMD64|x86_64)$' { return 'x64' }
    '^ARM64$' { return 'arm64' }
    default { throw "Unsupported Windows architecture: $architecture" }
  }
}

function Resolve-HongAiNodeRuntime {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
  )

  $architecture = Get-HongAiWindowsArchitecture
  $candidate = Join-Path $ProjectRoot 'runtime\node.exe'
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    return [pscustomobject]@{
      Path = (Resolve-Path -LiteralPath $candidate).Path
      Source = 'bundled'
      Architecture = $architecture
    }
  }
  throw 'Offline payload is missing its pinned runtime at runtime\node.exe. Customer installation never downloads or substitutes Node.js.'
}

function Assert-HongAiPortablePayload {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot,
    [Parameter(Mandatory = $true)]
    [string]$Architecture,
    [switch]$AllowInstalledState
  )

  $deliveryPath = Join-Path $ProjectRoot 'HONGAI-DELIVERY.json'
  $payloadManifestPath = Join-Path $ProjectRoot 'HONGAI-PAYLOAD.json'
  foreach ($manifestPath in @($deliveryPath, $payloadManifestPath)) {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
      throw "Offline payload is missing required manifest: $manifestPath"
    }
  }

  try {
    $delivery = Get-Content -LiteralPath $deliveryPath -Raw | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath $payloadManifestPath -Raw | ConvertFrom-Json
  } catch {
    throw "Offline payload manifest is malformed: $($_.Exception.Message)"
  }

  if (
    $delivery.schemaVersion -ne 2 -or
    $delivery.product -ne 'HONG AI Edge Cage' -or
    $delivery.bundleType -ne 'portable' -or
    $delivery.platform -ne 'windows' -or
    $delivery.architecture -ne $Architecture -or
    $delivery.payloadManifest -ne 'HONGAI-PAYLOAD.json'
  ) {
    throw 'HONGAI-DELIVERY.json does not describe this Windows portable payload and architecture.'
  }
  if ($manifest.schemaVersion -ne 1 -or $manifest.product -ne 'HONG AI Edge Cage') {
    throw 'HONGAI-PAYLOAD.json is not a supported HONG AI payload manifest.'
  }

  $packageMetadata = Get-Content -LiteralPath (Join-Path $ProjectRoot 'package.json') -Raw | ConvertFrom-Json
  if ([string]::IsNullOrWhiteSpace([string]$delivery.version) -or $delivery.version -ne $packageMetadata.version) {
    throw 'Portable delivery and package versions do not match.'
  }

  $rootPrefix = $ProjectRoot.TrimEnd('\') + '\'
  $declared = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $requiredEntries = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($requiredEntry in @(
    'HONGAI-DELIVERY.json',
    'package.json',
    'dist/src/cli.js',
    'runtime/node.exe',
    'node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js',
    "node_modules/@anthropic-ai/sandbox-runtime/vendor/srt-win/$Architecture/srt-win.exe",
    'node_modules/@anthropic-ai/claude-code/bin/claude.exe'
  )) {
    [void]$requiredEntries.Add($requiredEntry)
  }

  $entries = @($manifest.files)
  if ($entries.Count -lt $requiredEntries.Count -or $entries.Count -gt 100000) {
    throw 'Portable payload manifest contains an invalid number of file records.'
  }
  foreach ($entry in $entries) {
    $relativePath = [string]$entry.path
    $segments = $relativePath -split '/'
    $unsafeSegments = @($segments | Where-Object {
      [string]::IsNullOrWhiteSpace([string]$_) -or
      $_ -in @('.', '..') -or
      ([string]$_).Trim() -ne [string]$_ -or
      [string]$_ -match '[. ]$'
    })
    if (
      [string]::IsNullOrWhiteSpace($relativePath) -or
      $relativePath.Length -gt 512 -or
      $relativePath.Contains('\') -or
      $relativePath -match '[\x00-\x1f<>:"|?*]' -or
      $unsafeSegments.Count -gt 0
    ) {
      throw "Portable payload manifest contains an unsafe path: $relativePath"
    }
    if (-not $declared.Add($relativePath)) {
      throw "Portable payload manifest contains a duplicate or case-colliding path: $relativePath"
    }
    if ([string]$entry.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
      throw "Portable payload manifest contains an invalid SHA-256 value for $relativePath."
    }
    try {
      $expectedBytes = [UInt64]$entry.bytes
    } catch {
      throw "Portable payload manifest contains an invalid byte count for $relativePath."
    }
    if ([decimal]$expectedBytes -ne [decimal]$entry.bytes) {
      throw "Portable payload manifest contains a non-integer byte count for $relativePath."
    }

    $candidate = [IO.Path]::GetFullPath((Join-Path $ProjectRoot ($relativePath -replace '/', '\')))
    if (-not $candidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Portable payload path escapes the package root: $relativePath"
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "Portable payload entry is not a regular file: $relativePath"
    }
    if ([UInt64]$item.Length -ne $expectedBytes) {
      throw "Portable payload byte count mismatch: $relativePath"
    }
    $actualSha256 = Get-HongAiFileSha256 -Path $candidate
    if ($actualSha256 -ne [string]$entry.sha256) {
      throw "Portable payload SHA-256 mismatch: $relativePath"
    }
  }

  foreach ($requiredEntry in $requiredEntries) {
    if (-not $declared.Contains($requiredEntry)) {
      throw "Portable payload manifest is missing required file: $requiredEntry"
    }
  }

  foreach ($directory in Get-ChildItem -LiteralPath $ProjectRoot -Directory -Force -Recurse) {
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "Portable payload contains a reparse-point directory: $($directory.FullName)"
    }
  }
  foreach ($file in Get-ChildItem -LiteralPath $ProjectRoot -File -Force -Recurse) {
    $relativePath = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
    if ($relativePath -eq 'HONGAI-PAYLOAD.json') {
      continue
    }
    if ($AllowInstalledState -and $relativePath -eq '.edge-cage/windows-install-state.json') {
      continue
    }
    if (-not $declared.Contains($relativePath)) {
      throw "Portable payload contains an undeclared file: $relativePath"
    }
  }
}

function Get-HongAiOfflinePayload {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot,
    [switch]$VerifyPortableManifest,
    [switch]$AllowInstalledState
  )

  $runtime = Resolve-HongAiNodeRuntime -ProjectRoot $ProjectRoot
  if ($VerifyPortableManifest) {
    Assert-HongAiPortablePayload `
      -ProjectRoot $ProjectRoot `
      -Architecture $runtime.Architecture `
      -AllowInstalledState:$AllowInstalledState
  }
  $cliPath = Join-Path $ProjectRoot 'dist\src\cli.js'
  $srtCliPath = Join-Path $ProjectRoot 'node_modules\@anthropic-ai\sandbox-runtime\dist\cli.js'
  $srtWinPath = Join-Path $ProjectRoot "node_modules\@anthropic-ai\sandbox-runtime\vendor\srt-win\$($runtime.Architecture)\srt-win.exe"
  $claudePackage = Join-Path $ProjectRoot 'node_modules\@anthropic-ai\claude-code\package.json'
  $packageJsonPath = Join-Path $ProjectRoot 'package.json'
  foreach ($required in @($cliPath, $srtCliPath, $srtWinPath, $claudePackage, $packageJsonPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
      throw "Offline payload is incomplete; missing required file: $required"
    }
  }

  $nodeVersionText = (& $runtime.Path -p "process.versions.node").Trim()
  if ($LASTEXITCODE -ne 0 -or $nodeVersionText -notmatch '^(\d+)\.') {
    throw 'Unable to determine the offline Node.js runtime version.'
  }
  if ([int]$Matches[1] -lt 24) {
    throw "Node.js 24 or newer is required; detected $nodeVersionText."
  }

  return [pscustomobject]@{
    NodePath = $runtime.Path
    NodeSource = $runtime.Source
    Architecture = $runtime.Architecture
    NodeVersion = $nodeVersionText
    CliPath = $cliPath
    SrtCliPath = $srtCliPath
    SrtWinPath = $srtWinPath
    PackageJsonPath = $packageJsonPath
  }
}

function Assert-HongAiFreeSpace {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [UInt64]$MinimumFreeBytes = 3GB
  )

  $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
  $driveName = $root.TrimEnd('\').TrimEnd(':')
  $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
  if ([UInt64]$drive.Free -lt $MinimumFreeBytes) {
    throw "The installation volume requires at least $MinimumFreeBytes free bytes; available: $($drive.Free)."
  }
  return [UInt64]$drive.Free
}

function Get-HongAiFileSha256 {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $stream = [IO.File]::OpenRead($Path)
  $sha256 = [Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha256.ComputeHash($stream)
    return ([BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant())
  } finally {
    $sha256.Dispose()
    $stream.Dispose()
  }
}

function Invoke-HongAiNodeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$NodePath,
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,
    [Parameter(Mandatory = $true)]
    [string]$FailureMessage
  )

  & $NodePath $ScriptPath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FailureMessage (exit code $LASTEXITCODE)."
  }
}

function Get-HongAiSandboxStatus {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SrtWinPath
  )

  $output = & $SrtWinPath status 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the existing Windows sandbox installation: $($output -join [Environment]::NewLine)"
  }
  try {
    return (($output -join [Environment]::NewLine) | ConvertFrom-Json)
  } catch {
    throw 'Windows sandbox status returned malformed JSON.'
  }
}

function Test-HongAiSandboxPresent {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Status
  )

  if ($Status.user.user.exists -or $Status.user.user.group_exists -or $Status.user.cred_present) {
    return $true
  }
  if ($null -ne $Status.user.marker_version) {
    return $true
  }
  if ($null -ne $Status.wfp.filters -and [int]$Status.wfp.filters -gt 0) {
    return $true
  }
  return $Status.wfp.state -notin @('absent', 'none', 'cannot-read')
}

function Get-HongAiInstallStatePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
  )
  return (Join-Path $ProjectRoot '.edge-cage\windows-install-state.json')
}

function Read-HongAiInstalledState {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
  )

  $statePath = Get-HongAiInstallStatePath -ProjectRoot $ProjectRoot
  if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "Installation state is missing at $statePath. Complete the elevated offline installer before continuing."
  }
  try {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
  } catch {
    throw "Installation state is malformed: $($_.Exception.Message)"
  }
  if ($state.schemaVersion -ne 1 -or $state.product -ne 'HONG AI Edge Cage' -or $state.status -ne 'INSTALLED') {
    throw 'Installation state is invalid or has been uninstalled; refusing to continue.'
  }
  return $state
}

function Assert-HongAiInstalledConfig {
  param(
    [Parameter(Mandatory = $true)]
    [object]$State,
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
  )

  $actualHash = Get-HongAiFileSha256 -Path $ConfigPath
  if ([string]$State.configSha256 -ne $actualHash) {
    throw 'Customer configuration differs from the validated installation configuration. Reinstall deliberately instead of substituting an unapproved configuration at launch.'
  }
}

function Write-HongAiJsonAtomic {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [object]$Value,
    [string]$ScratchDirectory = ''
  )

  $directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Force -Path $directory | Out-Null
  $workingDirectory = $directory
  if (-not [string]::IsNullOrWhiteSpace($ScratchDirectory)) {
    $scratchItem = Get-Item -LiteralPath $ScratchDirectory -Force -ErrorAction Stop
    if (-not $scratchItem.PSIsContainer -or ($scratchItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "Atomic state scratch path must be a regular directory: $ScratchDirectory"
    }
    $workingDirectory = $scratchItem.FullName
    if ([IO.Path]::GetPathRoot($workingDirectory) -ne [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($directory))) {
      throw 'Atomic state scratch path must be on the same volume as the destination.'
    }
  }
  $temporaryPath = Join-Path $workingDirectory ".hongai-state-$PID-$([Guid]::NewGuid().ToString('N')).tmp"
  $backupPath = Join-Path $workingDirectory ".hongai-state-$PID-$([Guid]::NewGuid().ToString('N')).bak"
  $stream = $null
  try {
    $json = $Value | ConvertTo-Json -Depth 12
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("$json`n")
    $stream = [IO.FileStream]::new(
      $temporaryPath,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
    $stream.Dispose()
    $stream = $null

    if (Test-Path -LiteralPath $Path) {
      $existing = Get-Item -LiteralPath $Path -Force
      if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to replace a non-regular state file: $Path"
      }
      [IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
    } else {
      [IO.File]::Move($temporaryPath, $Path)
    }
  } finally {
    if ($null -ne $stream) {
      $stream.Dispose()
    }
    if (Test-Path -LiteralPath $temporaryPath) {
      Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $backupPath) {
      Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
  }
}
