[CmdletBinding()]
param([string]$EnginePath,[switch]$FreshEngine)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'DISPOSABLE_CI_ONLY'}
$output=Join-Path $PSScriptRoot 'integrated-build'
if(-not $FreshEngine){& (Join-Path $PSScriptRoot 'Build-Installer.ps1') -Destination $output}
$setup=Join-Path $output 'HONGAI-CAGE-Desktop-0.3.0-pilot.5-Windows-x64-Setup.exe'
$target=if($FreshEngine){'D:\HONGAI-CAGE-Fresh-QA\Desktop'}else{'D:\HONGAI-CAGE-Integrated-QA\Desktop'}
$prefix=if($FreshEngine){'fresh-'}else{''}
$env:HONGAI_CAGE_CI_RESULT=Join-Path $output ($prefix+'installer-result.json')
$installer=Start-Process -FilePath $setup -ArgumentList ('--install-for-ci "'+$target+'"') -Wait -PassThru
if($installer.ExitCode -ne 0){if(Test-Path $env:HONGAI_CAGE_CI_RESULT){Get-Content -LiteralPath $env:HONGAI_CAGE_CI_RESULT -Raw|Write-Host};throw 'INTEGRATED_INSTALLER_FAILED'}
$data=Join-Path (Split-Path $target -Parent) 'DesktopData'
$workspace=Join-Path (Split-Path $target -Parent) 'Workspace';$null=New-Item -ItemType Directory -Path $workspace -Force
if($FreshEngine){$receipt=Get-Content -LiteralPath (Join-Path $data 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json;if(-not $receipt.engineFreshlyInstalled){throw 'FRESH_ENGINE_PATH_WAS_NOT_EXERCISED'}}
$socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
$socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0));$port=$socket.LocalEndPoint.Port
$handoff=Join-Path $PSScriptRoot 'integrated-handoff.json'
[ordered]@{version=1;tool='clash';loopback=[ordered]@{protocol='http';host='127.0.0.1';mixedPort=$port};expectedEgressIp='8.8.8.8';routeId='0123456789abcdef01234567';generatedAt=[datetime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5|Set-Content $handoff -Encoding UTF8
$stop=Join-Path $data 'signals\qa.stop'
$test=[ordered]@{installer=$false;session=$false;nativeUI=$false;dailyAutomaticLaunch=$false;uninstall=$false;loginAttempted=$false;hostNetworkSettingsChanged=$false;customerAccepted=$false}
try{
    $test.installer=$true
    $shortcutDir=Join-Path (Split-Path $target -Parent) 'Shortcut-QA';$null=New-Item -ItemType Directory -Path $shortcutDir -Force
    $shell=New-Object -ComObject WScript.Shell;$linkFile=Join-Path $shortcutDir 'HONG AI CAGE.lnk';$stale=$shell.CreateShortcut($linkFile);$stale.Arguments='-File old-open-cage.ps1';$stale.Save()
    & (Join-Path $target 'New-DesktopShortcut.ps1') -InstallRoot $target -DesktopDirectory $shortcutDir
    $link=$shell.CreateShortcut($linkFile)
    if($link.Arguments -ne '' -or $link.TargetPath -ine (Join-Path $target 'HONGAI-CAGE.exe') -or $link.IconLocation -ine ((Join-Path $target 'resources\Claude.ico')+',0')){throw 'OFFICIAL_ICON_OR_SHORTCUT_REPAIR_FAILED'}
    Write-Host 'PASS official icon shortcut repair clears stale arguments without changing protected launcher'
    $sessionArguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $target 'Run-Session.ps1')+'" -DataRoot "'+$data+'" -Workspace "'+$workspace+'" -HandoffPath "'+$handoff+'" -StopFile "'+$stop+'" -MaximumSessionSeconds 45 -OfflineAcceptance'
    $session=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $sessionArguments -PassThru -WindowStyle Hidden
    if(-not $session.WaitForExit(180000)){$session.Kill();throw 'INSTALLED_SESSION_LIFECYCLE_TIMEOUT'}
    $state=Get-Content -LiteralPath (Join-Path $data 'session-status.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if($state.phase -ne 'STOPPED' -or -not $state.officialDesktopStarted -or $state.storageBudgetChecks -lt 1 -or $state.officialSourceKind -cne 'MSIX_PRIVATE_SIGNED_COPY' -or $state.officialFilesVerified -lt 5){$state|ConvertTo-Json -Depth 6|Write-Host;throw 'INTEGRATED_OFFICIAL_SESSION_NOT_ACCEPTED'}
    $test.session=$true
    $gui=Start-Process -FilePath (Join-Path $target 'HONGAI-CAGE.exe') -ArgumentList '--ui-smoke-test' -PassThru
    if(-not $gui.WaitForExit(15000) -or $gui.ExitCode -ne 0){throw 'INTEGRATED_NATIVE_UI_FAILED'}
    $test.nativeUI=$true
    $daily=Start-Process -FilePath (Join-Path $target 'HONGAI-CAGE.exe') -ArgumentList '--daily-launch-smoke-test' -PassThru
    if(-not $daily.WaitForExit(90000)){$daily.Kill();throw 'DAILY_AUTOMATIC_LAUNCH_TIMEOUT'}
    $dailyResult=Get-Content -LiteralPath (Join-Path $data 'daily-launch-test.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if(-not $dailyResult.automaticLaunch -or $dailyResult.settingsVisible){throw 'DAILY_LAUNCH_REPEATED_SETUP_OR_DID_NOT_START'}
    $test.dailyAutomaticLaunch=$true
    & (Join-Path $target 'Uninstall-Cage.ps1') -ConfirmUninstall
    if(Test-Path $target){throw 'INTEGRATED_UNINSTALL_DID_NOT_MOVE_OWN_APP'}
    $test.uninstall=$true
    Write-Host 'PASS integrated setup, official desktop session, native UI, and recoverable uninstall'
}catch{$test.error=$_.Exception.Message;throw}
finally{$socket.Dispose();$test|ConvertTo-Json|Set-Content (Join-Path $output ($prefix+'integrated-status.json')) -Encoding UTF8;if(Test-Path (Join-Path $data 'session-status.json')){Copy-Item -LiteralPath (Join-Path $data 'session-status.json') -Destination (Join-Path $output ($prefix+'session-status.json'))}}
