Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:PolicySubkey = 'SOFTWARE\Policies\Claude'

function Get-HongAiPilotPolicy {
    param([Parameter(Mandatory)][string]$ProxyUri)
    if ($ProxyUri -cnotmatch '^http://127\.0\.0\.1:[0-9]{4,5}$') { throw 'POLICY_PROXY_INVALID' }
    [ordered]@{
        egressProxyUrl = $ProxyUri
        secureVmFeaturesEnabled = 0
        isLocalDevMcpEnabled = 0
        isDesktopExtensionEnabled = 0
        isDesktopExtensionDirectoryEnabled = 0
        isClaudeCodeForDesktopEnabled = 0
        disableAutoUpdates = 1
    }
}

function Test-HongAiPolicyAvailability {
    foreach ($hive in @([Microsoft.Win32.Registry]::LocalMachine, [Microsoft.Win32.Registry]::CurrentUser)) {
        $key = $hive.OpenSubKey($script:PolicySubkey)
        try {
            if ($null -ne $key -and $key.ValueCount -gt 0) { throw 'EXISTING_CLAUDE_POLICY_REQUIRES_REVIEW' }
        } finally { if ($null -ne $key) { $key.Dispose() } }
    }
}

function Enable-HongAiPilotPolicy {
    param([Parameter(Mandatory)][string]$ProxyUri, [Parameter(Mandatory)][string]$StateDirectory)
    Test-HongAiPolicyAvailability
    $state = [IO.Path]::GetFullPath($StateDirectory)
    if ($state -notmatch '^[DE]:\\') { throw 'POLICY_BACKUP_MUST_USE_D_OR_E' }
    if (Test-Path -LiteralPath $state) {
        $item = Get-Item -LiteralPath $state -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'POLICY_STATE_REPARSE_POINT' }
    } else { $null = New-Item -ItemType Directory -Path $state }
    $backupPath = Join-Path $state 'policy-recovery.json'
    if (Test-Path -LiteralPath $backupPath) { throw 'POLICY_RECOVERY_PENDING_RUN_ROLLBACK_FIRST' }
    $old = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PolicySubkey)
    $keyExisted = $null -ne $old
    if ($null -ne $old) { $old.Dispose() }
    $plan = Get-HongAiPilotPolicy -ProxyUri $ProxyUri
    $backup = [ordered]@{ schema = 'hongai.claude-policy-recovery.v1'; keyExisted = $keyExisted; applied = $plan }
    # CreateNew preserves any pre-existing recovery data; persist recovery before the first registry write.
    $file = [IO.File]::Open($backupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($backup | ConvertTo-Json -Depth 4))
        $file.Write($bytes, 0, $bytes.Length); $file.Flush($true)
    } finally { $file.Dispose() }
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:PolicySubkey)
        try {
            foreach ($name in $plan.Keys) {
                $kind = if ($name -eq 'egressProxyUrl') { [Microsoft.Win32.RegistryValueKind]::String } else { [Microsoft.Win32.RegistryValueKind]::DWord }
                $key.SetValue($name, $plan[$name], $kind)
            }
            $key.Flush()
        } finally { $key.Dispose() }
    } catch {
        Restore-HongAiPilotPolicy -StateDirectory $state
        throw
    }
}

function Restore-HongAiPilotPolicy {
    param([Parameter(Mandatory)][string]$StateDirectory)
    $state = [IO.Path]::GetFullPath($StateDirectory)
    $backupPath = Join-Path $state 'policy-recovery.json'
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $backupPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 8192) { throw 'POLICY_RECOVERY_INVALID' }
    $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
    if ($backup.schema -cne 'hongai.claude-policy-recovery.v1') { throw 'POLICY_RECOVERY_SCHEMA_INVALID' }
    $expected = Get-HongAiPilotPolicy -ProxyUri ([string]$backup.applied.egressProxyUrl)
    if ($backup.keyExisted -isnot [bool] -or @($backup.applied.PSObject.Properties).Count -ne $expected.Count) { throw 'POLICY_RECOVERY_FIELDS_INVALID' }
    foreach ($name in $expected.Keys) {
        if ([string]$backup.applied.$name -cne [string]$expected[$name]) { throw 'POLICY_RECOVERY_VALUE_INVALID' }
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PolicySubkey, $true)
    try {
        if ($null -ne $key) {
            foreach ($name in $expected.Keys) {
                $value = $key.GetValue($name, $null)
                if ($null -ne $value -and [string]$value -cne [string]$expected[$name]) { throw 'POLICY_CHANGED_EXTERNALLY_MANUAL_REVIEW' }
            }
            foreach ($name in $expected.Keys) { $key.DeleteValue($name, $false) }
            $empty = $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0
        } else { $empty = $false }
    } finally { if ($null -ne $key) { $key.Dispose() } }
    if ($empty -and -not $backup.keyExisted) { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($script:PolicySubkey, $false) }
    Move-Item -LiteralPath $backupPath -Destination (Join-Path $state ('policy-restored-' + [guid]::NewGuid().ToString('N') + '.json'))
}

function Invoke-HongAiPilotPolicy {
    param([Parameter(Mandatory)][ValidateSet('Enable','Restore')][string]$Operation, [string]$ProxyUri)
    $state=Join-Path $PSScriptRoot '.state'
    if($Operation -eq 'Enable'){ $null=Get-HongAiPilotPolicy -ProxyUri $ProxyUri }
    $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($admin){
        if($Operation -eq 'Enable'){Enable-HongAiPilotPolicy -ProxyUri $ProxyUri -StateDirectory $state}
        else {Restore-HongAiPilotPolicy -StateDirectory $state}
        return
    }
    $ticket=[guid]::NewGuid().ToString('N')
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $helper=Join-Path $PSScriptRoot 'Policy-Elevation.ps1'
    $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -Operation '+$Operation+' -OriginalUserSid '+$sid+' -Ticket '+$ticket
    if($Operation -eq 'Enable'){ $args += ' -ProxyUri "'+$ProxyUri+'"' }
    # Elevate this small, fixed application-policy helper only. The official app stays non-admin.
    $worker=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Hidden -PassThru -Wait
    $resultPath=Join-Path $state ('elevation-'+$Operation.ToLowerInvariant()+'.json')
    if(-not(Test-Path -LiteralPath $resultPath -PathType Leaf)){throw 'POLICY_HELPER_NO_RESULT'}
    $result=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if($result.ticket -cne $ticket -or $worker.ExitCode -ne 0 -or -not $result.passed){throw 'POLICY_HELPER_FAILED_RECOVERY_MAY_BE_REQUIRED'}
}

Export-ModuleMember -Function Get-HongAiPilotPolicy,Test-HongAiPolicyAvailability,Enable-HongAiPilotPolicy,Restore-HongAiPilotPolicy,Invoke-HongAiPilotPolicy
