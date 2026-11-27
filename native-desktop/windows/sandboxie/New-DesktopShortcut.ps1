[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallRoot,[Parameter(Mandatory)][string]$DesktopDirectory)
$ErrorActionPreference='Stop'
$launcher=Join-Path $InstallRoot 'HONGAI-CAGE.exe';$icon=Join-Path $InstallRoot 'resources\Claude.ico'
if(-not(Test-Path -LiteralPath $launcher) -or -not(Test-Path -LiteralPath $icon)){throw 'SHORTCUT_PAYLOAD_OR_OFFICIAL_ICON_MISSING'}
$shell=New-Object -ComObject WScript.Shell
$link=$shell.CreateShortcut((Join-Path $DesktopDirectory 'HONG AI CAGE.lnk'))
$link.TargetPath=$launcher;$link.Arguments='';$link.WorkingDirectory=$InstallRoot;$link.IconLocation=$icon+',0';$link.Description='HONG AI CAGE - Claude Desktop isolated entry'
$link.Save()
