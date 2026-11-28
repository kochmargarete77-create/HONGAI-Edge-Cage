[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OldMsi,
    [Parameter(Mandatory)][string]$NewMsi,
    [Parameter(Mandatory)][string]$OutputDirectory
)
. (Join-Path $PSScriptRoot 'Msi-Common.ps1')
# This script is intentionally restricted to disposable hosted Windows CI.
# Never set these variables on a customer or developer PC to bypass the guard.
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') { throw 'DISPOSABLE_GITHUB_HOSTED_WINDOWS_RUNNER_REQUIRED_NO_LOCAL_INSTALL' }
$out=Assert-DataDriveDirectory $OutputDirectory
[void][IO.Directory]::CreateDirectory($out)
$oldPath=(Resolve-Path -LiteralPath $OldMsi).Path
$newPath=(Resolve-Path -LiteralPath $NewMsi).Path
foreach($p in @($oldPath,$newPath)){if($p -match '[\r\n"]'){throw 'UNSAFE_MSI_PATH'}}
$old=Get-Content -LiteralPath ($oldPath+'.json') -Raw|ConvertFrom-Json
$new=Get-Content -LiteralPath ($newPath+'.json') -Raw|ConvertFrom-Json
foreach($pair in @(@($oldPath,$old),@($newPath,$new))){
    if($pair[1].schema -cne 'hongai.windows-msi.v1' -or (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pair[1].msiSha256){throw 'MSI_MANIFEST_HASH_MISMATCH'}
}
if($old.upgradeCode -cne $new.upgradeCode -or [version]$old.productVersion -ge [version]$new.productVersion -or $old.productCode -ceq $new.productCode -or $old.payloadSha256 -ceq $new.payloadSha256){throw 'REAL_DISTINCT_PAYLOAD_AND_INCREASING_MAJOR_UPGRADE_REQUIRED'}
$installDir=Join-Path $env:LOCALAPPDATA 'Programs\HONG AI Environment Workbench'
$installedExe=Join-Path $installDir 'hongai-environment.exe'
$privateRoot=Join-Path $env:LOCALAPPDATA ('HONGAI-Environment-MsiTest-'+[guid]::NewGuid().ToString('N'))
$desktopLink=Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'HONG AI Environment.lnk'
$menuLink=Join-Path ([Environment]::GetFolderPath('Programs')) 'HONG AI Environment\HONG AI Environment.lnk'
if((Test-Path -LiteralPath $installDir) -or (Test-Path -LiteralPath $privateRoot) -or (Test-Path -LiteralPath $desktopLink) -or (Test-Path -LiteralPath $menuLink) -or (Test-Path -LiteralPath 'HKCU:\Software\HONGAI\EnvironmentWorkbenchInstaller')){throw 'RUNNER_NOT_CLEAN_REFUSING_EXISTING_CUSTOMER_STATE'}
$results=[Collections.Generic.List[object]]::new()
function Pass([string]$Name){$results.Add([pscustomobject]@{name=$Name;status='PASS'})}
function Assert([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
function Invoke-TestMsi([string]$Verb,[string]$Path,[string]$Log){
    $proc=Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList ('/'+$Verb+' "'+$Path+'" /qn /norestart /L*v "'+$Log+'"') -Wait -PassThru -WindowStyle Hidden
    if($proc.ExitCode -eq 3010){throw 'CI_INSTALLER_REQUESTED_REBOOT_NOT_ACCEPTED'}
    $proc.ExitCode
}
function InstalledHash(){ if(Test-Path -LiteralPath $installedExe){(Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()}else{''} }
function Assert-Shortcut([string]$Path){
    Assert (Test-Path -LiteralPath $Path) 'STABLE_SHORTCUT_MISSING'
    $shell=New-Object -ComObject WScript.Shell
    try{$link=$shell.CreateShortcut($Path);Assert ($link.TargetPath -ieq $installedExe -and [string]::IsNullOrEmpty($link.Arguments)) 'SHORTCUT_MUST_TARGET_STABLE_NOARGS_ENTRY'}finally{Close-MsiObject $shell}
}
function Read-WorkbenchAddress([string]$Root){
    Add-Type -AssemblyName System.Security
    $context=[Text.Encoding]::UTF8.GetBytes('HONGAI-MCP-V1|'+$Root)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{$entropy=$hasher.ComputeHash($context)}finally{$hasher.Dispose()}
    $sealed=[IO.File]::ReadAllBytes((Join-Path $Root 'workbench-address.sealed'))
    $raw=[Security.Cryptography.ProtectedData]::Unprotect($sealed,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    try{[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json}finally{[Array]::Clear($raw,0,$raw.Length)}
}
function Get-NetworkHash(){
    $value=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)|ConvertTo-Json -Depth 5 -Compress
    $hasher=[Security.Cryptography.SHA256]::Create();try{[Convert]::ToBase64String($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))}finally{$hasher.Dispose()}
}
$installer=$null;$db=$null;$server=$null;$canary=$null;$address=$null;$http=$null
$installedNew=$false;$installedOld=$false;$failure=$null
try{
    # Validate authoring before allowing Windows Installer to execute the package.
    $installer=New-Object -ComObject WindowsInstaller.Installer
    foreach($entry in @(@($oldPath,$old),@($newPath,$new))){
        $db=$installer.OpenDatabase([string]$entry[0],0)
        $tableNames=@(Get-MsiRows $db 'SELECT `Name` FROM `_Tables`' 1|ForEach-Object{$_[0]})
        foreach($forbidden in @('CustomAction','ServiceInstall','ServiceControl','MsiServiceConfig','RemoveFile','Environment')){Assert ($tableNames -notcontains $forbidden) 'FORBIDDEN_SIDE_EFFECT_TABLE'}
        $props=@{};foreach($row in @(Get-MsiRows $db 'SELECT `Property`,`Value` FROM `Property`' 2)){$props[$row[0]]=$row[1]}
        Assert (-not $props.ContainsKey('ALLUSERS') -and -not $props.ContainsKey('REINSTALLMODE')) 'PERUSER_MAJOR_UPGRADE_AUTHORING_REQUIRED'
        Assert ($props.ProductCode -ceq $entry[1].productCode -and $props.ProductVersion -ceq $entry[1].productVersion -and $props.UpgradeCode -ceq $entry[1].upgradeCode) 'MSI_VERSION_IDENTITY_MANIFEST_MISMATCH'
        $actions=@{};foreach($row in @(Get-MsiRows $db 'SELECT `Action`,`Sequence` FROM `InstallExecuteSequence`' 2)){$actions[$row[0]]=[int]$row[1]}
        Assert ($actions.InstallInitialize -lt $actions.RemoveExistingProducts -and $actions.RemoveExistingProducts -lt $actions.ProcessComponents) 'MAJOR_UPGRADE_MUST_RUN_INSIDE_ROLLBACK_TRANSACTION'
        Assert (@(Get-MsiRows $db 'SELECT `File_` FROM `MsiFileHash`' 1).Count -eq @(Get-MsiRows $db 'SELECT `File` FROM `File`' 1).Count) 'UNVERSIONED_FILES_REQUIRE_MSI_HASH_ROWS'
        $summary=Get-MsiProperty $db SummaryInformation @(0)
        try{Assert ((([int](Get-MsiProperty $summary Property @(15))) -band 8) -eq 8) 'PERUSER_NO_ELEVATED_SUMMARY_REQUIRED'}finally{Close-MsiObject $summary}
        Close-MsiObject $db;$db=$null
    }
    Pass 'MSI_STATIC_SCOPE_AND_TRANSACTION_VALIDATION'
    $networkBefore=Get-NetworkHash
    # A separate owned process must survive upgrades and uninstallation.
    $canary=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 600"' -PassThru -WindowStyle Hidden
    Assert ((Invoke-TestMsi i $oldPath (Join-Path $out 'install-old.log')) -eq 0) 'OLD_INSTALL_FAILED';$installedOld=$true
    Assert ((InstalledHash) -ceq $old.payloadSha256) 'OLD_INSTALLED_PAYLOAD_SHA_MISMATCH'
    Assert-Shortcut $desktopLink;Assert-Shortcut $menuLink
    Pass 'PERUSER_INSTALL_EXACT_OLD_PAYLOAD_AND_SHORTCUTS'
    $receiptText=& $installedExe environment install --root $privateRoot
    Assert ($LASTEXITCODE -eq 0) 'PRIVATE_WORKBENCH_INSTALL_FAILED'
    $receipt=$receiptText|ConvertFrom-Json
    Assert ($receipt.root -ceq $privateRoot -and $receipt.runtime -like ($privateRoot+'\runtime-*\hongai-environment.exe')) 'PRIVATE_RUNTIME_NOT_OWNED'
    $requestFile=Join-Path $out 'test-settings.json'
    Write-JsonUtf8 $requestFile @{version=1;proxyUrl='http://127.0.0.1:1';expectedExit='1.1.1.1';timeZone='America/Los_Angeles';hostAssessmentConfirmed=$false}
    $null=& $installedExe environment configure --root $privateRoot --request $requestFile
    Assert ($LASTEXITCODE -eq 0) 'PRIVATE_SETTINGS_NOT_SAVED'
    $sentinel=Join-Path $privateRoot 'ci-upgrade-sentinel.txt';[IO.File]::WriteAllText($sentinel,'CI-only data must survive MSI upgrade and uninstall.')
    $settingsFile=Join-Path $privateRoot 'environment-settings.sealed'
    $settingsHash=(Get-FileHash -LiteralPath $settingsFile -Algorithm SHA256).Hash
    $receiptHash=(Get-FileHash -LiteralPath (Join-Path $privateRoot 'environment-receipt.json') -Algorithm SHA256).Hash
    # Start only the private runtime, never lock the MSI-owned EXE.
    $server=Start-Process -FilePath $receipt.runtime -ArgumentList ('environment open --root "'+$privateRoot+'" --no-browser --minutes 10') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $out 'workbench-stdout.txt') -RedirectStandardError (Join-Path $out 'workbench-stderr.txt')
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do{try{$address=Read-WorkbenchAddress $privateRoot;break}catch{Start-Sleep -Milliseconds 150}}while([DateTime]::UtcNow -lt $deadline)
    Assert ($null -ne $address -and $address.pid -eq $server.Id) 'PRIVATE_WORKBENCH_ADDRESS_NOT_READY'
    Add-Type -AssemblyName System.Net.Http
    $handler=[Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false
    $http=[Net.Http.HttpClient]::new($handler);$http.Timeout=[TimeSpan]::FromSeconds(5)
    $http.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$address.token)
    Assert (($http.GetAsync($address.baseUrl+'/api/ping').GetAwaiter().GetResult()).StatusCode -eq 200) 'PRIVATE_WORKBENCH_NOT_RESPONDING'
    Pass 'RUNNING_PRIVATE_WORKBENCH_WITH_SEALED_SETTINGS'
    Assert ((Invoke-TestMsi i $newPath (Join-Path $out 'upgrade-new.log')) -eq 0) 'MAJOR_UPGRADE_FAILED';$installedNew=$true;$installedOld=$false
    Assert ((InstalledHash) -ceq $new.payloadSha256 -and (InstalledHash) -cne $old.payloadSha256) 'UPGRADE_DID_NOT_REPLACE_UNVERSIONED_EXE'
    Assert-Shortcut $desktopLink;Assert-Shortcut $menuLink
    Assert ((Get-FileHash -LiteralPath $settingsFile -Algorithm SHA256).Hash -ceq $settingsHash -and (Get-FileHash -LiteralPath (Join-Path $privateRoot 'environment-receipt.json') -Algorithm SHA256).Hash -ceq $receiptHash -and (Test-Path -LiteralPath $sentinel)) 'UPGRADE_CHANGED_PRIVATE_STATE'
    Assert (-not $server.HasExited -and -not $canary.HasExited) 'UPGRADE_STOPPED_RESIDENT_PROCESS'
    Pass 'REAL_DISTINCT_UNVERSIONED_EXE_MAJOR_UPGRADE_STATE_AND_PROCESS_PRESERVED'
    $downgradeCode=Invoke-TestMsi i $oldPath (Join-Path $out 'downgrade-rejected.log')
    Assert ($downgradeCode -ne 0 -and (InstalledHash) -ceq $new.payloadSha256) 'DOWNGRADE_NOT_SAFELY_REJECTED'
    Pass 'DOWNGRADE_REJECTED_NEW_PAYLOAD_UNCHANGED'
    Assert ((Invoke-TestMsi x $newPath (Join-Path $out 'uninstall-new.log')) -eq 0) 'MSI_UNINSTALL_FAILED';$installedNew=$false
    Assert (-not (Test-Path -LiteralPath $installedExe) -and -not (Test-Path -LiteralPath $desktopLink) -and -not (Test-Path -LiteralPath $menuLink)) 'UNINSTALL_LEFT_INSTALL_FILES_OR_SHORTCUTS'
    Assert ((Test-Path -LiteralPath $sentinel) -and (Get-FileHash -LiteralPath $settingsFile -Algorithm SHA256).Hash -ceq $settingsHash -and (Get-FileHash -LiteralPath (Join-Path $privateRoot 'environment-receipt.json') -Algorithm SHA256).Hash -ceq $receiptHash) 'UNINSTALL_REMOVED_PRIVATE_STATE'
    Assert (-not $server.HasExited -and -not $canary.HasExited) 'UNINSTALL_STOPPED_RESIDENT_PROCESS'
    Assert (($http.GetAsync($address.baseUrl+'/api/ping').GetAwaiter().GetResult()).StatusCode -eq 200) 'UNINSTALL_BROKE_RUNNING_PRIVATE_SERVER'
    Assert ((Get-NetworkHash) -ceq $networkBefore) 'CI_DNS_CONFIGURATION_CHANGED'
    Pass 'UNINSTALL_REMOVES_MSI_ONLY_PRESERVES_PRIVATE_DATA_SERVER_AND_CANARY'
}catch{$failure=$_.Exception.Message;throw}finally{
    # Stop only our explicitly created fixture. Do not enumerate/kill product names.
    if($null -ne $http -and $null -ne $address){try{$request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,$address.baseUrl+'/api/stop');$request.Headers.Add('Origin',$address.baseUrl);$request.Content=[Net.Http.StringContent]::new('{}',[Text.Encoding]::UTF8,'application/json');$null=$http.SendAsync($request).GetAwaiter().GetResult();$request.Dispose()}catch{}}
    if($null -ne $server -and -not $server.HasExited){if(-not $server.WaitForExit(5000)){Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue}}
    if($null -ne $canary -and -not $canary.HasExited){Stop-Process -Id $canary.Id -Force -ErrorAction SilentlyContinue}
    if($null -ne $http){$http.Dispose()}
    if($installedNew){$null=Invoke-TestMsi x $newPath (Join-Path $out 'cleanup-new.log')}
    elseif($installedOld){$null=Invoke-TestMsi x $oldPath (Join-Path $out 'cleanup-old.log')}
    Close-MsiObject $db;Close-MsiObject $installer
    Write-JsonUtf8 (Join-Path $out 'MSI-VALIDATION.json') ([ordered]@{schema='hongai.windows-msi-test.v1';passed=($null -eq $failure);oldVersion=$old.productVersion;newVersion=$new.productVersion;oldPayloadSha256=$old.payloadSha256;newPayloadSha256=$new.payloadSha256;newMsiSha256=$new.msiSha256;runner=$env:ImageOS;results=@($results);failure=$failure;privateStateRetention='RETAINED_ON_EPHEMERAL_RUNNER_NOT_UPLOADED';officialAccountTest='NOT_RUN';nativeAllEgressEnforcement=$false;hardwareSimulation=$false;customerReadyFullEnvironment=$false})
}
