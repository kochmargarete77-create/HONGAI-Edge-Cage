[CmdletBinding()]
param([string]$ReportPath)
$ErrorActionPreference='Stop'
$checks=[Collections.Generic.List[object]]::new()
function Add-Check([string]$Name,[string]$Status,[string]$Action){$checks.Add([ordered]@{name=$Name;status=$Status;action=$Action})}
$os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
Add-Check 'Windows version' $(if([int]$os.BuildNumber -ge 19041){'PASS'}else{'BLOCK'}) 'Windows 10 build 19041 or newer is required by the current official Claude package.'
Add-Check 'CPU architecture' $(if($cpu.Architecture -eq 9){'PASS'}else{'BLOCK'}) 'This engine supports x64 Windows. ARM64 Windows is not accepted by this installer.'
Add-Check 'PowerShell' $(if($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5){'PASS'}else{'BLOCK'}) 'Use the bundled EXE; it selects Windows PowerShell 5.1 automatically.'
Add-Check 'Execution policy environment' $(if($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage'){'PASS'}else{'BLOCK'}) 'This build requires ordinary application execution. Do not disable Smart App Control, WDAC, Defender, SIP or Gatekeeper to make installation pass; publisher approval/signing or a compatible release is required.'
Add-Check 'AppX commands' $(if(Get-Command Get-AppxPackage -ErrorAction SilentlyContinue){'PASS'}else{'BLOCK'}) 'Windows AppX deployment components must be available. Do not reset AppX or remove application data automatically.'
Add-Check '.NET Framework' $(if(Test-Path "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"){'PASS'}else{'BLOCK'}) 'Windows .NET Framework 4.x is required. No Python, Node, Homebrew, WSL or virtual machine is required.'
$service=Get-Service SbieSvc -ErrorAction SilentlyContinue
if($service){
    $image=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc').ImagePath
    if($image -match '^"?(.+?SbieSvc\.exe)"?(?:\s.*)?$'){
        $engine=Split-Path $matches[1] -Parent
        $text=(Get-Item (Join-Path $engine 'Start.exe')).VersionInfo.FileVersion
        Add-Check 'Existing isolation engine' $(if($text -match '(\d+(?:\.\d+){1,3})' -and [version]$matches[1] -ge [version]'5.74.1'){'PASS'}else{'BLOCK'}) 'An existing older Sandboxie installation requires an approved component update; never replace another product silently.'
        $wfp=(& (Join-Path $engine 'SbieIni.exe') query GlobalSettings NetworkEnableWFP|Out-String).Trim()
        Add-Check 'Existing kernel network filter' $(if($wfp -eq 'y'){'PASS'}else{'BLOCK'}) 'Existing Sandboxie has WFP disabled. Review its other sandboxes before changing this shared component.'
    }else{Add-Check 'Existing isolation engine' 'BLOCK' 'Existing service path is not recognized; no shared driver changes were made.'}
}else{Add-Check 'Isolation component' 'PASS' 'The original signed Sandboxie Classic installer is included; install once with administrator permission.'}
Add-Check 'Restart policy' 'PASS' 'No host restart, Wi-Fi, TUN, DNS, route, firewall default or ToDesk changes will be made.'
$report=[ordered]@{schema='hongai.install-preflight.v1';os=$os.Caption;build=$os.BuildNumber;architecture=$cpu.Architecture;ready=@($checks|Where-Object {$_.status -ceq 'BLOCK'}).Count -eq 0;checks=$checks.ToArray();hostNetworkSettingsChanged=$false;rebootPerformed=$false}
if($ReportPath){[IO.File]::WriteAllText($ReportPath,($report|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))}
[pscustomobject]$report
