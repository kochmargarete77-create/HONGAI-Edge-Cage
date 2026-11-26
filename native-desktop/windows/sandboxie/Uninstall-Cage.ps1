[CmdletBinding()]
param([switch]$ConfirmUninstall)
$ErrorActionPreference='Stop'
if(-not $ConfirmUninstall){throw '卸载请使用 -ConfirmUninstall；将保留隔离数据与恢复副本。'}
$root=$PSScriptRoot
$receipt=Get-Content -LiteralPath (Join-Path $root 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($receipt.schema -cne 'hongai.cage.installation.v1' -or $receipt.installRoot -cne $root){throw 'UNINSTALL_OWNERSHIP_NOT_CONFIRMED'}
if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count -gt 0){throw '先关闭 Claude 与隔离会话。'}
$data=[string]$receipt.dataRoot
$ownership=Join-Path $data 'box-ownership.json'
if(Test-Path $ownership){
    $owned=Get-Content $ownership -Raw -Encoding UTF8|ConvertFrom-Json
    if($owned.ownerSid -cne $receipt.ownerSid -or $owned.box -notmatch '^HONGAI_CAGE_[a-f0-9]{12}$'){throw 'BOX_OWNERSHIP_MISMATCH'}
    $ini=Join-Path $receipt.enginePath 'SbieIni.exe'
    & $ini set $owned.box ForceProcess|Out-Null
    & $ini set $owned.box Enabled n|Out-Null
    if((& $ini query $owned.box ForceProcess|Out-String).Trim()){throw 'FORCE_RULE_REMOVAL_NOT_CONFIRMED'}
}
$parent=Split-Path $root -Parent;$recovery=Join-Path $parent 'Recovery';$null=New-Item -ItemType Directory -Path $recovery -Force
$target=Join-Path $recovery ('Desktop-uninstalled-'+[guid]::NewGuid().ToString('N'))
if((Resolve-Path -LiteralPath $root).Path -cne $root -or -not $target.StartsWith($recovery+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'UNINSTALL_MOVE_SCOPE_MISMATCH'}
$link=Join-Path ([Environment]::GetFolderPath('Desktop')) 'HONG AI CAGE.lnk'
if(Test-Path $link){$shell=New-Object -ComObject WScript.Shell;if($shell.CreateShortcut($link).TargetPath -ieq (Join-Path $root 'HONGAI-CAGE.exe')){Move-Item -LiteralPath $link -Destination (Join-Path $recovery ('Cage-shortcut-'+[guid]::NewGuid().ToString('N')+'.lnk'))}}
Set-Location -LiteralPath $parent;[Environment]::CurrentDirectory=$parent
Move-Item -LiteralPath $root -Destination $target
[ordered]@{uninstalled=$true;recoverableApplication=$target;dataPreserved=$data;sharedIsolationComponentPreserved=$true;hostNetworkSettingsChanged=$false;officialClaudeRemoved=$false}|ConvertTo-Json
