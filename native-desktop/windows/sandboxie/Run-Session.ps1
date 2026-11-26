[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DataRoot,
    [Parameter(Mandatory)][string]$Workspace,
    [string]$HandoffPath,
    [Parameter(Mandatory)][string]$StopFile,
    [int]$ParentProcessId=0,
    [int]$MaximumSessionSeconds=0,
    [switch]$OfflineAcceptance,
    [string]$OfficialExecutableOverride
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
$safeDataRoot=$false
trap {
    if($safeDataRoot){[IO.File]::WriteAllText((Join-Path $DataRoot 'session-status.json'),([ordered]@{phase='BLOCKED';error=$_.Exception.Message}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
    exit 1
}
$runtime=$PSScriptRoot
$DataRoot=[IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
$receipt=Get-Content -LiteralPath (Join-Path $DataRoot 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($receipt.schema -cne 'hongai.cage.installation.v1' -or $receipt.dataRoot -cne $DataRoot -or $receipt.ownerSid -cne $sid){throw 'CAGE_INSTALLATION_OWNERSHIP_MISMATCH'}
$safeDataRoot=$true
if(($OfflineAcceptance -or $OfficialExecutableOverride) -and $env:GITHUB_ACTIONS -ne 'true'){throw 'TEST_OVERRIDES_REQUIRE_DISPOSABLE_CI'}
$Workspace=(Resolve-Path -LiteralPath $Workspace -ErrorAction Stop).Path.TrimEnd('\')
if($Workspace -match '["\r\n*?]' -or $Workspace.Length -lt 4 -or $Workspace.StartsWith('\\') -or $Workspace -ieq $env:USERPROFILE -or $Workspace.StartsWith($DataRoot,[StringComparison]::OrdinalIgnoreCase) -or $Workspace.StartsWith($runtime,[StringComparison]::OrdinalIgnoreCase)){throw 'SELECT_A_SEPARATE_LOCAL_PROJECT_FOLDER'}
$stop=[IO.Path]::GetFullPath($StopFile)
if(-not $stop.StartsWith((Join-Path $DataRoot 'signals\'),[StringComparison]::OrdinalIgnoreCase)){throw 'STOP_SIGNAL_SCOPE_MISMATCH'}
foreach($folder in '.tmp','signals','transport'){$null=New-Item -ItemType Directory -Path (Join-Path $DataRoot $folder) -Force}
$env:TEMP=Join-Path $DataRoot '.tmp';$env:TMP=$env:TEMP
Import-Module (Join-Path $runtime 'HONGAI.DesktopGuard.psm1') -Force
$enrolled=Join-Path $DataRoot 'enrolled-handoff.json'
$newEnrollment=-not [string]::IsNullOrWhiteSpace($HandoffPath)
if($newEnrollment){$handoff=Read-HongAiClashHandoff -Path $HandoffPath}
else{$HandoffPath=$enrolled;$handoff=Read-HongAiClashHandoff -Path $HandoffPath -MaximumAge ([timespan]::MaxValue)}
if(-not $OfflineAcceptance){$null=Test-HongAiClashRoute -Handoff $handoff -Passes 3}
$engine=[IO.Path]::GetFullPath([string]$receipt.enginePath)
foreach($protected in @($DataRoot,$runtime,$engine)){$protected=$protected.TrimEnd('\');if($Workspace.StartsWith($protected+'\',[StringComparison]::OrdinalIgnoreCase)-or $protected.StartsWith($Workspace+'\',[StringComparison]::OrdinalIgnoreCase)-or $Workspace -ieq $protected){throw 'WORKSPACE_OVERLAPS_PROTECTED_RUNTIME_OR_CONFIGURATION'}}
$start=Join-Path $engine 'Start.exe';$ini=Join-Path $engine 'SbieIni.exe'
foreach($file in @($start,$ini,(Join-Path $engine 'SbieSvc.exe'))){if((Get-AuthenticodeSignature -LiteralPath $file).Status -ne 'Valid'){throw 'SIGNED_ENGINE_COMPONENT_VERIFICATION_FAILED'}}
function Invoke-Engine([string]$File,[string[]]$Arguments,[int]$Timeout=12000){
    # Start.exe parses switches directly from GetCommandLine: quoting /box or
    # /silent makes them a child program name instead of an engine switch.
    $quoted=@($Arguments|ForEach-Object {if($_ -match '["\r\n]'){throw 'UNSAFE_ENGINE_ARGUMENT'};if($_.Length -gt 0 -and $_ -notmatch '\s'){$_}else{'"'+($_ -replace '(\\+)$','$1$1')+'"'}}) -join ' '
    $info=[Diagnostics.ProcessStartInfo]::new($File,$quoted);$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $worker=[Diagnostics.Process]::Start($info)
    try{$stdout=$worker.StandardOutput.ReadToEndAsync();$stderr=$worker.StandardError.ReadToEndAsync();if(-not $worker.WaitForExit($Timeout)){$worker.Kill();throw ('ENGINE_COMMAND_TIMEOUT '+[IO.Path]::GetFileName($File)+' '+($Arguments -join ' '))};$output=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult();if($worker.ExitCode -ne 0){throw ('ENGINE_COMMAND_FAILED '+$worker.ExitCode+' '+[IO.Path]::GetFileName($File)+' '+($Arguments -join ' '))};return $output.Trim()}finally{$worker.Dispose()}
}
function Read-Setting([string]$Section,[string]$Key){Invoke-Engine $ini @('query',$Section,$Key)}
function Set-Setting([string]$Section,[string]$Key,[string]$Value,[switch]$Append){$operation=if($Append){'append'}else{'set'};$null=Invoke-Engine $ini @($operation,$Section,$Key,$Value)}
if((Read-Setting 'GlobalSettings' 'NetworkEnableWFP') -ne 'y'){throw 'KERNEL_NETWORK_FILTER_NOT_ENABLED_INSTALL_REVIEW_REQUIRED'}
if(-not [string]::IsNullOrWhiteSpace((Read-Setting 'GlobalSettings' 'NetworkAccess'))){throw 'EXISTING_GLOBAL_NETWORK_RULES_REQUIRE_REVIEW'}
$sha=[Security.Cryptography.SHA256]::Create();try{$suffix=(-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid))|ForEach-Object {$_.ToString('x2')})).Substring(0,12)}finally{$sha.Dispose()}
$box='HONGAI_CAGE_'+$suffix
function Box-Pids {
    $lines=@((Invoke-Engine $start @("/box:$box",'/listpids')) -split '\r?\n'|Where-Object {$_ -match '^\d+$'})
    if(@($lines).Count -eq 0){throw 'BOX_PROCESS_ENUMERATION_UNVERIFIED'}
    $count=[int]$lines[0];$pids=@($lines|Select-Object -Skip 1|ForEach-Object {[int]$_})
    if($pids.Count -ne $count){throw 'BOX_PROCESS_ENUMERATION_INCOMPLETE'}
    return $pids
}
$ownership=Join-Path $DataRoot 'box-ownership.json'
$existing=Read-Setting $box 'Enabled'
if($existing){if(-not(Test-Path $ownership)){throw 'EXISTING_BOX_NOT_OWNED_BY_CAGE'};$owner=Get-Content $ownership -Raw -Encoding UTF8|ConvertFrom-Json;if($owner.box -cne $box -or $owner.ownerSid -cne $sid){throw 'BOX_OWNERSHIP_MISMATCH'};if(@(Box-Pids).Count -gt 0){throw 'CAGE_SESSION_ALREADY_RUNNING'}}
else{
    [IO.File]::WriteAllText($ownership,([ordered]@{box=$box;ownerSid=$sid}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
if($OfficialExecutableOverride){$executable=[IO.Path]::GetFullPath($OfficialExecutableOverride)}else{
    $package=Get-AppxPackage -Name Claude|Where-Object Publisher -Match 'Anthropic, PBC'|Select-Object -First 1
    if(-not $package){throw 'OFFICIAL_CLAUDE_DESKTOP_MUST_BE_INSTALLED'}
    $executable=Join-Path $package.InstallLocation 'app\Claude.exe'
}
$signature=Get-AuthenticodeSignature -LiteralPath $executable
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Anthropic'){throw 'OFFICIAL_CLAUDE_SIGNATURE_INVALID'}
if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count -gt 0){throw 'EXIT_EXISTING_CLAUDE_BEFORE_START'}
$hostPolicy=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Policies\Claude')
try{if($hostPolicy -and $hostPolicy.ValueCount -gt 0){throw 'EXISTING_ENTERPRISE_POLICY_REQUIRES_REVIEW'}}finally{if($hostPolicy){$hostPolicy.Dispose()}}
Add-Type -Path (Join-Path $runtime 'resources\HONGAI-SessionProxy.dll')
$broker=$null;$admitted=$false;$startedAt=[datetime]::UtcNow
$statusPath=Join-Path $DataRoot 'session-status.json'
$status=[ordered]@{schema='hongai.cage.session.v1';phase='PREPARING';box=$box;exitIp=$handoff.ExpectedEgressIp;mode='SIGNED_DESKTOP_SANDBOX_PILOT';loginAttempted=$false;globalNetworkChanges=0}
function Save-Status{[IO.File]::WriteAllText($statusPath,($status|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))}
Save-Status
try{
    $broker=[HongAi.SessionProxy]::new($handoff.ProxyPort,30000)
    Set-Setting $box 'NetworkAccess' '*,Block'
    Set-Setting $box 'NetworkAccess' ("*,Allow;Port=$($broker.Port);Address=127.0.0.1;Protocol=TCP") -Append
    Set-Setting $box 'FileRootPath' (Join-Path $DataRoot 'Box')
    Set-Setting $box 'DropAdminRights' 'y'
    Set-Setting $box 'ProcessNumberLimit' '64'
    Set-Setting $box 'TotalMemoryLimit' '2147483648'
    Set-Setting $box 'ProcessMemoryLimit' '1073741824'
    Set-Setting $box 'BlockNetworkFiles' 'y'
    Set-Setting $box 'OpenFilePath' ($Workspace+'\*')
    Set-Setting $box 'OpenFilePath' ((Join-Path $DataRoot 'transport')+'\*') -Append
    Set-Setting $box 'WriteFilePath' '%AppData%\Claude\*'
    Set-Setting $box 'WriteFilePath' '%Local AppData%\Claude\*' -Append
    Set-Setting $box 'WriteFilePath' '%UserProfile%\.claude\*' -Append
    Set-Setting $box 'ClosedFilePath' ((Join-Path $DataRoot 'signals')+'\*')
    foreach($path in @(($runtime+'\*'),$enrolled,(Join-Path $DataRoot 'installation.json'),'%SystemRoot%\Sandboxie.ini','%AppData%\io.github.clash-verge-rev.clash-verge-rev\*','%AppData%\Clash Verge\*','%UserProfile%\.config\clash\*','%UserProfile%\.config\mihomo\*','%Local AppData%\Google\Chrome\User Data\*','%Local AppData%\Microsoft\Edge\User Data\*')){Set-Setting $box 'ClosedFilePath' $path -Append}
    Set-Setting $box 'ForceProcess' 'Claude.exe'
    Set-Setting $box 'Enabled' 'y'
    $active=Read-Setting $box 'NetworkAccess'
    if($active -notmatch '\*,Block' -or $active -notmatch [regex]::Escape("Port=$($broker.Port);Address=127.0.0.1;Protocol=TCP")){throw 'BOX_KERNEL_POLICY_READBACK_FAILED'}
    $result=Join-Path $DataRoot ('transport\policy-'+[guid]::NewGuid().ToString('N')+'.txt')
    # The signed-engine helper writes only into the dedicated empty box. Its HKCU
    # changes are virtualized; host enterprise/application policy is untouched.
    $control=Join-Path $DataRoot ('transport\control-'+[guid]::NewGuid().ToString('N')+'.exe')
    Copy-Item -LiteralPath (Join-Path $runtime 'resources\HONGAI-SessionControl.exe') -Destination $control
    $null=Invoke-Engine $start @("/box:$box",'/silent','/hide_window','/wait',$control,$box,[string]$broker.Port,$result)
    if(-not(Test-Path $result)-or [IO.File]::ReadAllText($result).Trim([char]0xFEFF) -cne "POLICY_READY|$box|$($broker.Port)"){throw 'VIRTUALIZED_PROXY_POLICY_NOT_CONFIRMED'}
    Start-Sleep -Seconds 2
    if(-not $OfflineAcceptance){$null=Test-HongAiClashRoute -Handoff $handoff -Passes 1 -DelayMilliseconds 0}
    $broker.Refresh(16000)
    if($newEnrollment){Copy-Item -LiteralPath $HandoffPath -Destination $enrolled -Force}
    [IO.File]::WriteAllText((Join-Path $DataRoot 'workspace.json'),([ordered]@{workspace=$Workspace}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $arguments=@("/box:$box",'/silent',"/env:HTTP_PROXY=http://127.0.0.1:$($broker.Port)","/env:HTTPS_PROXY=http://127.0.0.1:$($broker.Port)","/env:ALL_PROXY=http://127.0.0.1:$($broker.Port)",$executable,"--proxy-server=http://127.0.0.1:$($broker.Port)",'--proxy-bypass-list=<-loopback>','--disable-quic','--disk-cache-size=268435456','--media-cache-size=134217728')
    $null=Invoke-Engine $start $arguments
    Start-Sleep -Seconds 2
    $boxPids=@(Box-Pids)
    if(@(Get-Process Claude -ErrorAction SilentlyContinue|Where-Object {$_.Id -in $boxPids}).Count -eq 0){throw 'OFFICIAL_DESKTOP_DID_NOT_START_IN_OWN_BOX'}
    $admitted=$true;$status.phase='RUNNING';$status.proxyPort=$broker.Port;$status.officialDesktopStarted=$true;$status.observedBoxProcesses=$boxPids.Count;Save-Status
    $nextStorageCheck=[datetime]::UtcNow.AddSeconds(20)
    while($true){
        Start-Sleep -Seconds 3
        if(Test-Path -LiteralPath $stop){break}
        if($ParentProcessId -gt 0 -and -not(Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue)){break}
        if($MaximumSessionSeconds -gt 0 -and ([datetime]::UtcNow-$startedAt).TotalSeconds -ge $MaximumSessionSeconds){break}
        $currentPids=@(Box-Pids)
        if($currentPids.Count -eq 0){break}
        if($currentPids.Count -gt 64){throw 'OWN_SANDBOX_PROCESS_BUDGET_EXCEEDED'}
        if([datetime]::UtcNow -ge $nextStorageCheck){
            $bytes=0L;$count=0
            foreach($file in [IO.Directory]::EnumerateFiles((Join-Path $DataRoot 'Box'),'*',[IO.SearchOption]::AllDirectories)){$count++;$bytes+=([IO.FileInfo]::new($file)).Length;if($count -gt 30000 -or $bytes -gt 3GB){throw 'OWN_SANDBOX_STORAGE_BUDGET_REACHED'}}
            $nextStorageCheck=[datetime]::UtcNow.AddSeconds(30)
        }
        if(-not $OfflineAcceptance){$null=Test-HongAiClashRoute -Handoff $handoff -Passes 1 -DelayMilliseconds 0}
        $broker.Refresh(16000)
    }
    $status.phase='STOPPED'
} catch {$status.phase='BLOCKED';$status.error=$_.Exception.Message;throw}
finally{
    if($broker){$broker.Dispose()}
    if($admitted -or $broker){try{$null=Invoke-Engine $start @("/box:$box",'/terminate')}catch{$status.recovery='OWN_BOX_TERMINATION_REQUIRES_REVIEW_NETWORK_GATEWAY_CLOSED'}}
    Save-Status
}
