[CmdletBinding()]
param([ValidateSet('NetworkAssessment','DesktopPilot','FullDesktop')][string]$Target='NetworkAssessment',[ValidateSet('NotRequired','Unknown','Cloud','LocalVM')][string]$CoworkMode='NotRequired')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'RUN_WITH_NATIVE_64BIT_WINDOWS_POWERSHELL_5_1'}
$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
Import-Module (Join-Path $PSScriptRoot 'Routing-Policy.psm1') -Force
$facts=@{
    platform='Windows';target=$Target;coworkMode=$CoworkMode
    hardwareArchitecture=$null;osVersion=$null;windowsBuild=$null;windowsProductType=$null
    freeMemoryGB=$null;totalMemoryGB=$null;dataVolumeFreeGB=$null
    officialInstallKind='UNKNOWN';officialVersion=$null;tunCandidateCount=$null
    managedPolicyPresent=$null;existingClaudeStatePresent=$null;remoteToolProcessPresent=$null
    rosettaTranslated=$false;collector='NATIVE_POWERSHELL_5_1'
}
try{
    $os=Get-CimInstance Win32_OperatingSystem
    $facts.osVersion=[string]$os.Version;$facts.windowsBuild=[int]$os.BuildNumber;$facts.windowsProductType=[int]$os.ProductType
    $facts.freeMemoryGB=[Math]::Round($os.FreePhysicalMemory/1MB,2);$facts.totalMemoryGB=[Math]::Round($os.TotalVisibleMemorySize/1MB,2)
}catch{}
try{
    $arch=@(Get-CimInstance Win32_Processor|Select-Object -ExpandProperty Architecture -Unique)
    if($arch.Count -eq 1){switch([int]$arch[0]){9{$facts.hardwareArchitecture='x64'}12{$facts.hardwareArchitecture='arm64'}}}
}catch{}
try{
    $volume=[IO.Path]::GetPathRoot($PSScriptRoot).TrimEnd('\')
    $disk=Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='"+$volume+"'")
    if($disk){$facts.dataVolumeFreeGB=[Math]::Round($disk.FreeSpace/1GB,2)}
}catch{}
try{
    $package=@(Get-AppxPackage -Name Claude -ErrorAction Stop|Where-Object {$_.Publisher -match 'Anthropic, PBC' -and $_.PackageFamilyName -ceq 'Claude_pzs8sxrjxfjjc'}|Sort-Object Version -Descending)
    if($package.Count){$facts.officialInstallKind='MSIX_REGISTERED_CURRENT_USER';$facts.officialVersion=[string]$package[0].Version}else{$facts.officialInstallKind='NO_MATCHING_MSIX_FOUND_WIN32_NOT_INSPECTED'}
}catch{}
try{$facts.tunCandidateCount=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Clash|mihomo|wintun|sing-box|Meta Tunnel'}).Count}catch{}
try{$facts.managedPolicyPresent=(Test-Path 'HKLM:\SOFTWARE\Policies\Claude') -or (Test-Path 'HKCU:\SOFTWARE\Policies\Claude')}catch{}
try{
    $paths=@((Join-Path $env:APPDATA 'Claude'),(Join-Path $env:LOCALAPPDATA 'Claude'),(Join-Path $env:LOCALAPPDATA 'Packages\Claude_pzs8sxrjxfjjc'))
    $facts.existingClaudeStatePresent=@($paths|Where-Object {Test-Path -LiteralPath $_}).Count -gt 0
}catch{}
try{$facts.remoteToolProcessPresent=@(Get-Process -ErrorAction Stop|Where-Object {$_.ProcessName -match '^(ToDesk|TeamViewer|SunloginClient|RustDesk)'}).Count -gt 0}catch{}
Get-HongAiDeviceRoute -Facts $facts|ConvertTo-Json -Depth 8
