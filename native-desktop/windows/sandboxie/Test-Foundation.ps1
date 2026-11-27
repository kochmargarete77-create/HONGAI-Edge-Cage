[CmdletBinding()]
param([ValidateSet('classic','plus')][string]$EngineFlavor='classic')
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows'){throw 'DISPOSABLE_GITHUB_CI_ONLY_DO_NOT_RUN_ON_CUSTOMER_HOST'}
$root=Join-Path $PSScriptRoot 'build'
if($root -notmatch '^D:\\'){throw 'CI_PROJECT_DATA_MUST_USE_D_DRIVE'}
$null=New-Item -ItemType Directory -Path $root -Force
$env:TEMP=$root;$env:TMP=$root
if(Get-Service -Name SbieSvc,SbieDrv -ErrorAction SilentlyContinue){throw 'EXISTING_SANDBOXIE_NOT_OWNED_BY_THIS_TEST'}
$asset=if($EngineFlavor -eq 'classic'){'Sandboxie-Classic-x64-v5.74.1.exe'}else{'Sandboxie-Plus-x64-v1.19.1.exe'}
$expectedHash=if($EngineFlavor -eq 'classic'){'4f97400854b7b984dedc5bd057b9f6886eb13a2cc29ed38b0094ebbe5483d57e'}else{'443b528766f4e6448632fd94afa7df5d9e1c52e13940db79139d4070da3aa384'}
$installer=Join-Path $root $asset
Invoke-WebRequest -UseBasicParsing -Uri ('https://github.com/sandboxie-plus/Sandboxie/releases/download/v1.19.1/'+$asset) -OutFile $installer
if((Get-FileHash $installer -Algorithm SHA256).Hash -ine $expectedHash){throw 'UPSTREAM_INSTALLER_HASH_MISMATCH'}
$signature=Get-AuthenticodeSignature -LiteralPath $installer
if($signature.Status -ne 'Valid'){throw 'UPSTREAM_INSTALLER_SIGNATURE_INVALID'}
$install='D:\HONGAI-Sandboxie-CI'
if(Test-Path $install){throw 'TEST_INSTALL_TARGET_EXISTS'}
$arguments='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /NOICONS /MERGETASKS=!DesktopIcon,!AutoStartEntry,!AddRunSandboxed /DIR="'+$install+'" /LOG="'+(Join-Path $root 'installer.log')+'"'
if($EngineFlavor -eq 'classic'){$arguments='/S /D='+$install}
$p=Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru
if($p.ExitCode -ne 0){throw "SIGNED_ENGINE_INSTALL_FAILED_OR_REBOOT_REQUIRED $($p.ExitCode)"}
Get-CimInstance Win32_Process -Filter "Name='SbieCtrl.exe'" -ErrorAction SilentlyContinue|Where-Object {$_.ExecutablePath -like ($install+'\*')}|ForEach-Object {Stop-Process -Id $_.ProcessId}
$ini=Join-Path $install 'SbieIni.exe';$start=Join-Path $install 'Start.exe'
$box='HONGAI_CI_Fixture';$results=@();$listener=$null;$alternate=$null;$six=$null
function Set-Box([string]$section,[string]$key,[string]$value,[switch]$Append){
    $operation=if($Append){'append'}else{'set'}
    & $ini $operation $section $key $value
    if($LASTEXITCODE -ne 0){throw "SBIE_CONFIGURATION_COMMAND_FAILED $key"}
}
function Check-Fixture([string]$mode,[int]$port,[int]$expected,[string]$label){
    Start-Sleep -Seconds 2
    $report=Join-Path $root ('reports\'+[guid]::NewGuid().ToString('N')+'.txt')
    $arguments='/box:'+$box+' /silent /hide_window /wait "'+(Join-Path $root 'fixture.exe')+'" '+$mode+' '+$box+' "'+$report+'" "'+$root+'" '+$port
    $child=Start-Process -FilePath $start -ArgumentList $arguments -PassThru
    if(-not $child.WaitForExit(15000)){throw "SANDBOX_FIXTURE_LAUNCH_TIMEOUT $label"}
    if(-not(Test-Path -LiteralPath $report)){throw "SANDBOX_RESULT_MISSING $label launcher=$($child.ExitCode)"}
    $actual=[IO.File]::ReadAllText($report)
    if($actual -cne "$expected|$box"){throw "FIXTURE_FAILED $label actual=$actual"}
    $script:results += $label;Write-Host "PASS $label"
}
try{
    foreach($folder in 'reports','private','workspace'){$null=New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force}
    [IO.File]::WriteAllText((Join-Path $root 'private\secret.txt'),'own fixture only')
    $compiler="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    & $compiler /nologo /platform:x64 /target:exe ("/out:"+(Join-Path $root 'fixture.exe')) (Join-Path $PSScriptRoot 'Fixture.cs')
    if($LASTEXITCODE -ne 0){throw 'FIXTURE_COMPILE_FAILED'}
    Copy-Item -LiteralPath (Join-Path $root 'fixture.exe') -Destination (Join-Path $root 'secondary-fixture.exe')
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start();$port=$listener.LocalEndpoint.Port
    $alternate=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$alternate.Start();$other=$alternate.LocalEndpoint.Port
    $six=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback,0);$six.Start();$sixPort=$six.LocalEndpoint.Port
    Set-Box 'GlobalSettings' 'NetworkEnableWFP' 'y'
    Set-Box $box 'Enabled' 'y'
    Set-Box $box 'FileRootPath' (Join-Path $root 'box')
    Set-Box $box 'DropAdminRights' 'y'
    Set-Box $box 'BlockNetworkFiles' 'y'
    Set-Box $box 'NetworkAccess' '*,Block'
    Set-Box $box 'NetworkAccess' ("*,Allow;Port=$port;Address=127.0.0.1;Protocol=TCP") -Append
    Set-Box $box 'OpenFilePath' (Join-Path $root 'reports\*')
    Set-Box $box 'OpenFilePath' (Join-Path $root 'workspace\*') -Append
    Set-Box $box 'ClosedFilePath' (Join-Path $root 'private\*')
    $wfp=(& $ini query GlobalSettings NetworkEnableWFP|Out-String).Trim()
    if($wfp -ne 'y'){throw 'KERNEL_CONFIGURATION_READBACK_FAILED'}
    # The engine is a fresh installation on this disposable runner. Restart its
    # own services before admitting any fixture; no customer host is involved.
    Stop-Service SbieSvc -ErrorAction Stop
    & sc.exe stop SbieDrv | Out-Null
    Start-Sleep -Seconds 2
    Start-Service SbieSvc
    Check-Fixture 'identity' $port 0 'kernel box identity is exact'
    Check-Fixture 'connect' $port 0 'selected numeric loopback endpoint works'
    Check-Fixture 'connect' $other 13 'alternate loopback endpoint is denied'
    Check-Fixture 'ipv6' $sixPort 13 'IPv6 alternate route is denied'
    Check-Fixture 'nested' $port 0 'different MCP-like child retains approved endpoint'
    Check-Fixture 'nested' $other 13 'different MCP-like child cannot bypass network rule'
    Check-Fixture 'read-secret' $port 13 'ungranted host fixture is unreadable'
    Check-Fixture 'workspace' $port 0 'approved workspace remains usable'
    Check-Fixture 'try-change-policy' $port 0 'sandboxed tool configuration change attempt completed'
    $activeRules=(& $ini query $box NetworkAccess | Out-String)
    if($activeRules -notmatch '\*,Block' -or $activeRules -notmatch [regex]::Escape("Port=$port;Address=127.0.0.1;Protocol=TCP")){throw 'SANDBOXED_TOOL_CHANGED_HOST_NETWORK_RULES'}
    Write-Host 'PASS sandboxed tool cannot replace host sandbox network policy'
    if(-not(Test-Path (Join-Path $root 'workspace\approved-result.txt'))){throw 'WORKSPACE_WRITE_WAS_NOT_SHARED_AS_EXPECTED'}
    $listener.Stop()
    Check-Fixture 'connect' $port 13 'proxy loss leaves sandbox offline'
    Check-Fixture 'nested' $other 13 'proxy loss never opens alternate route for tools'
    & (Join-Path $PSScriptRoot 'Test-OfficialDesktop.ps1') -EnginePath $install -BoxName $box -Root $root -ProxyPort $port
    [ordered]@{passed=$results.Count;mode='SIGNED_ENGINE_FOUNDATION_ONLY';officialDesktopAccepted=$false;customerAccepted=$false;signer=$signature.SignerCertificate.Subject;hostNetworkSettingsChanged=$false;scope='fresh disposable CI runner only'} | ConvertTo-Json | Set-Content (Join-Path $root 'foundation-status.json') -Encoding UTF8
} catch {
    $failure=$_.Exception.Message
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddMinutes(-12)} -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -match 'Sandboxie|Application Error|.NET Runtime'} | Select-Object -First 25 TimeCreated,ProviderName,Id,Message)
    [ordered]@{passed=$results.Count;failure=$failure;events=$events;customerAccepted=$false} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $root 'foundation-status.json') -Encoding UTF8
    throw
} finally {
    if($listener){$listener.Stop()};if($alternate){$alternate.Stop()};if($six){$six.Stop()}
    if(Test-Path $start){& $start ("/box:"+$box) /terminate | Out-Null}
    $uninstall=Join-Path $install 'unins000.exe'
    $uninstallArgs='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    if($EngineFlavor -eq 'classic'){$uninstall=$installer;$uninstallArgs='/remove /S'}
    if(Test-Path $uninstall){$null=Start-Process -FilePath $uninstall -ArgumentList $uninstallArgs -Wait -PassThru}
}
