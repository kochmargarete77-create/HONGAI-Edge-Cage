[CmdletBinding()]
param([string]$Destination,[switch]$NoShortcut)
$ErrorActionPreference='Stop'
$payload=Join-Path $PSScriptRoot 'payload'
$checks=Join-Path $payload 'CHECKSUMS-SHA256.txt'
if(-not(Test-Path $checks)){throw 'INSTALL_PAYLOAD_MISSING'}
if(-not $Destination){
    $drive=if(Test-Path 'E:\'){'E:'}elseif(Test-Path 'D:\'){'D:'}else{throw 'D_OR_E_DATA_DRIVE_REQUIRED'}
    $Destination=$drive+'\HONGAI-CAGE\DesktopGuard'
}
$target=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
if($target -notmatch '^[DE]:\\[^\\]+\\[^\\]+$'){throw 'USE_A_DEDICATED_D_OR_E_INSTALL_FOLDER'}
$cursor=$target
while($cursor -and $cursor.Length -gt 3){
    if(Test-Path -LiteralPath $cursor){$item=Get-Item -LiteralPath $cursor -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_PATH_LINK_DENIED'}}
    $cursor=Split-Path $cursor -Parent
}
$manifest=Get-Content (Join-Path $payload 'PILOT-MANIFEST.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($manifest.mode -cne 'DESKTOP_GUARD_PILOT' -or $manifest.formalCustomerRelease){throw 'INSTALL_MODE_REQUIRES_REVIEW'}
$list=@()
foreach($line in Get-Content $checks -Encoding UTF8){
    if($line -notmatch '^([A-Fa-f0-9]{64})  (.+)$'){throw 'INSTALL_CHECKSUM_FORMAT'}
    $hash=$matches[1];$relative=$matches[2]
    $source=[IO.Path]::GetFullPath((Join-Path $payload $relative))
    if(-not $source.StartsWith($payload+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'INSTALL_PAYLOAD_TRAVERSAL'}
    if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $hash){throw 'INSTALL_HASH_MISMATCH'}
    $list += [pscustomobject]@{Source=$source;Relative=$relative;Hash=$hash}
}
$old=$false
if(Test-Path -LiteralPath $target){
    $ownerFile=Join-Path $target '.hongai-install.json'
    if(-not(Test-Path $ownerFile)){throw 'EXISTING_FOLDER_NOT_OWNED_BY_INSTALLER'}
    $owner=Get-Content $ownerFile -Raw -Encoding UTF8|ConvertFrom-Json
    if($owner.product -cne 'HONGAI.DesktopGuard' -or $owner.path -cne $target){throw 'INSTALL_OWNERSHIP_MISMATCH'}
    if(Test-Path (Join-Path $target '.state\native-boundary.json')){throw 'RECOVER_NATIVE_BOUNDARY_BEFORE_UPGRADE'}
    if(Test-Path (Join-Path $target '.state\policy-recovery.json')){throw 'RECOVER_APP_POLICY_BEFORE_UPGRADE'}
    if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count -gt 0){throw 'CLOSE_CLAUDE_BEFORE_UPGRADE'}
    $old=$true
}
$stage=$target+'.install-'+[guid]::NewGuid().ToString('N')
$null=New-Item -ItemType Directory -Path $stage -Force
foreach($entry in $list){
    $dest=Join-Path $stage $entry.Relative
    $null=New-Item -ItemType Directory -Path (Split-Path $dest) -Force
    Copy-Item -LiteralPath $entry.Source -Destination $dest
    if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $entry.Hash){throw 'INSTALL_STAGE_VERIFY_FAILED'}
}
Copy-Item -LiteralPath $checks -Destination $stage
$ownership=[ordered]@{product='HONGAI.DesktopGuard';version=$manifest.version;path=$target;installedUtc=[datetime]::UtcNow.ToString('o');customerAccepted=$false}
[IO.File]::WriteAllText((Join-Path $stage '.hongai-install.json'),($ownership|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
$backup=$null
if($old){
    $recovery=$target.Substring(0,2)+'\HONGAI-CAGE-Recovery'
    $null=New-Item -ItemType Directory -Path $recovery -Force
    $backup=Join-Path $recovery ('DesktopGuard-'+[guid]::NewGuid().ToString('N'))
    $resolved=(Resolve-Path -LiteralPath $target).Path
    if($resolved -cne $target){throw 'INSTALL_MOVE_SCOPE_MISMATCH'}
    Move-Item -LiteralPath $resolved -Destination $backup
}
try{Move-Item -LiteralPath $stage -Destination $target}
catch{if($backup -and -not(Test-Path $target)){Move-Item -LiteralPath $backup -Destination $target};throw}
if(-not $NoShortcut){
    $desktop=[Environment]::GetFolderPath('Desktop')
    $linkPath=Join-Path $desktop 'HONG AI CAGE 桌面守卫（测试）.lnk'
    $shell=New-Object -ComObject WScript.Shell
    $link=$shell.CreateShortcut($linkPath)
    $link.TargetPath=Join-Path $target '01-启动Claude桌面守卫-PILOT.cmd'
    $link.WorkingDirectory=$target
    $link.Description='HONG AI CAGE official desktop network guard pilot'
    $link.Save()
}
[pscustomobject]@{Installed=$true;Path=$target;Version=$manifest.version;Files=$list.Count;OriginalBackup=$backup;ClaudeLaunched=$false;GlobalNetworkChanges=0;CustomerAccepted=$false}|ConvertTo-Json
