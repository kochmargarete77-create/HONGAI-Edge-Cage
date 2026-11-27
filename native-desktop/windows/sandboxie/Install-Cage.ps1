[CmdletBinding()]
param([string]$Destination,[switch]$NoShortcut,[string]$ResultPath,[string]$OriginalUserSid,[string]$OriginalDesktop)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
$report=[ordered]@{installed=$false;phase='VERIFY';hostNetworkSettingsChanged=$false;rebootPerformed=$false;customerAccepted=$false}
try {
    if(-not [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMIN_REQUIRED_FOR_SIGNED_ISOLATION_COMPONENT'}
    $uiWorkers=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -match '(?i)Cage-UI\.ps1'})
    if($uiWorkers.Count -or @(Get-Process 'HONGAI-CAGE' -ErrorAction SilentlyContinue).Count){throw 'EXIT_RUNNING_CAGE_BEFORE_UPGRADE_NO_AUTOMATIC_PROCESS_TERMINATION'}
    if(-not $OriginalUserSid){$OriginalUserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    $ownerSid=[Security.Principal.SecurityIdentifier]::new($OriginalUserSid)
    if(-not $OriginalDesktop){$OriginalDesktop=[Environment]::GetFolderPath('Desktop')}
    $payload=Join-Path $PSScriptRoot 'payload'
    $checks=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'CHECKSUMS-SHA256.txt') -Encoding UTF8
    foreach($line in $checks){
        if($line -notmatch '^([A-Fa-f0-9]{64})  (.+)$'){throw 'INSTALL_MANIFEST_INVALID'}
        $hash=$matches[1];$relative=$matches[2];$file=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot $relative))
        if(-not $file.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or (Get-FileHash -LiteralPath $file).Hash -ine $hash){throw 'INSTALL_PAYLOAD_VERIFICATION_FAILED'}
    }
    $env:TEMP=Join-Path $PSScriptRoot '.tmp';$env:TMP=$env:TEMP;$null=New-Item -ItemType Directory -Path $env:TEMP -Force
    $report.phase='COMPATIBILITY'
    $preflight=& (Join-Path $PSScriptRoot 'Test-Compatibility.ps1') -ReportPath (Join-Path $PSScriptRoot 'compatibility-report.json')
    if(-not $preflight.ready){throw ('COMPATIBILITY_BLOCK: '+(($preflight.checks|Where-Object status -EQ 'BLOCK'|ForEach-Object action) -join ' '))}
    if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count -gt 0){throw 'EXIT_CLAUDE_BEFORE_INSTALL'}
    $report.phase='OFFICIAL_DEPENDENCY'
    $official=& (Join-Path $PSScriptRoot 'Ensure-Official.ps1') -OriginalUserSid $ownerSid.Value -RequireCatalogVersion
    if(-not $official){throw 'SUPPORTED_OFFICIAL_CLAUDE_X64_MSIX_NOT_INSTALLED'}
    $officialSignature=Get-AuthenticodeSignature -LiteralPath (Join-Path $official.InstallLocation 'app\Claude.exe')
    if($officialSignature.Status -ne 'Valid' -or $officialSignature.SignerCertificate.Subject -notmatch 'Anthropic, PBC'){throw 'OFFICIAL_CLAUDE_SIGNATURE_INVALID'}
    if(-not $Destination){$drive=$null;foreach($candidate in @('E:\','D:\')){try{$info=[IO.DriveInfo]::new($candidate);if($info.IsReady -and $info.DriveType -eq 'Fixed' -and $info.AvailableFreeSpace -ge 5GB){$drive=$candidate.TrimEnd('\');break}}catch{}};$Destination=if($drive){$drive+'\HONGAI-CAGE\Desktop'}else{Join-Path $env:ProgramFiles 'HONGAI-CAGE\Desktop'}}
    $target=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if($target -match '["\r\n*?]' -or $target.Length -lt 8 -or $target.StartsWith('\\')){throw 'INSTALL_PATH_INVALID'}
    $parent=Split-Path $target -Parent;$data=Join-Path $parent 'DesktopData';$core=Join-Path $parent 'Sandboxie-Core'
    $cursor=$target
    while($cursor.Length -gt 3){if(Test-Path $cursor){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_LINK_PATH_REJECTED'}};$cursor=Split-Path $cursor -Parent}
    if(Test-Path $target){
        $old=Get-Content -LiteralPath (Join-Path $target 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if($old.schema -cne 'hongai.cage.installation.v1' -or $old.installRoot -cne $target){throw 'INSTALL_FOLDER_NOT_OWNED_BY_CAGE'}
    }
    if(Test-Path $data){$existingData=Get-Content -LiteralPath (Join-Path $data 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json;if($existingData.schema -cne 'hongai.cage.installation.v1' -or $existingData.ownerSid -cne $ownerSid.Value -or $existingData.dataRoot -cne $data){throw 'EXISTING_DATA_FOLDER_NOT_OWNED_BY_THIS_INSTALLATION'}}
    $null=New-Item -ItemType Directory -Path $parent -Force
    if((Get-PSDrive ($target.Substring(0,1))).Free -lt 5GB){throw 'NEED_AT_LEAST_5_GB_FREE_FOR_PROFILE_AND_WORKING_HEADROOM'}
    $report.phase='ISOLATION_COMPONENT'
    $service=Get-Service SbieSvc -ErrorAction SilentlyContinue
    $fresh=$null -eq $service
    if($fresh){
        if(Test-Path $core){throw 'ISOLATION_COMPONENT_DIRECTORY_ALREADY_EXISTS'}
        $vendor=Join-Path $PSScriptRoot 'vendor\Sandboxie-Classic-x64-v5.74.1.exe'
        if((Get-AuthenticodeSignature $vendor).Status -ne 'Valid'){throw 'UPSTREAM_SIGNED_INSTALLER_INVALID'}
        # NSIS /D is the final, unquoted argument by upstream design.
        $process=Start-Process -FilePath $vendor -ArgumentList ('/S /D='+$core) -Wait -PassThru -WindowStyle Hidden
        if($process.ExitCode -ne 0){throw ('ISOLATION_COMPONENT_INSTALL_FAILED '+$process.ExitCode)}
    }else{
        $image=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc').ImagePath
        if($image -notmatch '^"?(.+?SbieSvc\.exe)"?(?:\s.*)?$'){throw 'EXISTING_ENGINE_PATH_UNRECOGNIZED'}
        $core=Split-Path $matches[1] -Parent
    }
    foreach($component in @('Start.exe','SbieIni.exe','SbieSvc.exe')){if((Get-AuthenticodeSignature -LiteralPath (Join-Path $core $component)).Status -ne 'Valid'){throw 'INSTALLED_ENGINE_SIGNATURE_INVALID'}}
    $versionText=(Get-Item (Join-Path $core 'Start.exe')).VersionInfo.FileVersion
    if($versionText -notmatch '(\d+(?:\.\d+){1,3})'){throw 'ENGINE_VERSION_UNRECOGNIZED'}
    $engineVersion=[version]$matches[1]
    if($engineVersion -lt [version]'5.74.1'){throw 'EXISTING_ENGINE_REQUIRES_SEPARATE_UPDATE'}
    $ini=Join-Path $core 'SbieIni.exe'
    $wfp=(& $ini query GlobalSettings NetworkEnableWFP|Out-String).Trim()
    if($wfp -ne 'y'){
        if(-not $fresh){throw 'EXISTING_ENGINE_WFP_DISABLED_MANUAL_REVIEW_REQUIRED'}
        & $ini set GlobalSettings NetworkEnableWFP y|Out-Null
        $controllers=@(Get-CimInstance Win32_Process -Filter "Name='SbieCtrl.exe'" -ErrorAction SilentlyContinue|Where-Object {$_.ExecutablePath -like ($core+'\*')})
        foreach($controller in $controllers){Stop-Process -Id $controller.ProcessId}
        # This branch applies only to the freshly installed, unused component.
        Stop-Service SbieSvc
        & sc.exe stop SbieDrv|Out-Null
        Start-Sleep -Seconds 2
        Start-Service SbieSvc
        if((& $ini query GlobalSettings NetworkEnableWFP|Out-String).Trim() -ne 'y'){throw 'KERNEL_POLICY_INITIALIZATION_NOT_CONFIRMED'}
    }
    $null=New-Item -ItemType Directory -Path $data -Force
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
    foreach($identity in @($ownerSid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
    Set-Acl -LiteralPath $data -AclObject $acl
    $stage=$target+'.stage-'+[guid]::NewGuid().ToString('N');$null=New-Item -ItemType Directory -Path $stage
    Copy-Item -Path (Join-Path $payload '*') -Destination $stage -Recurse
    $receipt=[ordered]@{schema='hongai.cage.installation.v1';version='0.3.0-pilot.5';ownerSid=$ownerSid.Value;installRoot=$target;dataRoot=$data;enginePath=$core;engineFreshlyInstalled=$fresh;installedUtc=[datetime]::UtcNow.ToString('o');customerAccepted=$false}
    $json=$receipt|ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $stage 'installation.json'),$json,[Text.UTF8Encoding]::new($false))
    $backup=$null
    if(Test-Path $target){$recovery=Join-Path $parent 'Recovery';$null=New-Item -ItemType Directory -Path $recovery -Force;$backup=Join-Path $recovery ('Desktop-'+[guid]::NewGuid().ToString('N'));if((Resolve-Path -LiteralPath $target).Path -cne $target){throw 'UPGRADE_MOVE_SCOPE_MISMATCH'};Move-Item -LiteralPath $target -Destination $backup}
    $report.phase='COMMIT'
    try{
        Move-Item -LiteralPath $stage -Destination $target
        $receiptPath=Join-Path $data 'installation.json';$pending=$receiptPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        [IO.File]::WriteAllText($pending,$json,[Text.UTF8Encoding]::new($false))
        if(Test-Path -LiteralPath $receiptPath){[IO.File]::Replace($pending,$receiptPath,$receiptPath+'.previous')}else{[IO.File]::Move($pending,$receiptPath)}
    }catch{
        if(Test-Path -LiteralPath $target){$failed=Join-Path $parent ('Desktop.failed-'+[guid]::NewGuid().ToString('N'));if([IO.Path]::GetDirectoryName($target) -cne $parent){throw 'UPGRADE_ROLLBACK_SCOPE_MISMATCH'};Move-Item -LiteralPath $target -Destination $failed}
        if($backup -and -not(Test-Path $target)){Move-Item -LiteralPath $backup -Destination $target};throw
    }
    if(-not $NoShortcut){& (Join-Path $target 'New-DesktopShortcut.ps1') -InstallRoot $target -DesktopDirectory $OriginalDesktop}
    $report.installed=$true;$report.phase='INSTALLED';$report.installRoot=$target;$report.dataRoot=$data;$report.enginePath=$core;$report.version=$receipt.version;$report.officialVersion=[string]$official.Version
}catch{$report.error=$_.Exception.Message;throw}
finally{if($ResultPath){[IO.File]::WriteAllText($ResultPath,($report|ConvertTo-Json),[Text.UTF8Encoding]::new($false))};$report|ConvertTo-Json}
