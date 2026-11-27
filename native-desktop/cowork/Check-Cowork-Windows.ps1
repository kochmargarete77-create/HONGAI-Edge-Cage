[CmdletBinding()]
param([ValidateSet('Unknown','Cloud','LocalVM')][string]$Mode='Unknown',[string]$OutputPath)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
Import-Module (Join-Path $PSScriptRoot 'Readiness-Policy.psm1') -Force
$facts=@{osVersion=[Environment]::OSVersion.Version.ToString();process64Bit=[Environment]::Is64BitProcess;virtualMachinePlatformEnabled=$null;hypervisorPresent=$null;hnsPresent=$null;vmcomputePresent=$null;officialMsixPresent=$null;freeMemoryGB=$null;totalMemoryGB=$null}
try{$os=Get-CimInstance Win32_OperatingSystem;$facts.osVersion=[string]$os.Version;$facts.freeMemoryGB=[Math]::Round($os.FreePhysicalMemory/1MB,2);$facts.totalMemoryGB=[Math]::Round($os.TotalVisibleMemorySize/1MB,2)}catch{}
try{$facts.hypervisorPresent=[bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent}catch{}
try{$feature=Get-CimInstance Win32_OptionalFeature -Filter "Name='VirtualMachinePlatform'";if($feature){$facts.virtualMachinePlatformEnabled=$feature.InstallState -eq 1}}catch{}
foreach($entry in @(@{key='hnsPresent';name='hns'},@{key='vmcomputePresent';name='vmcompute'})){
    try{$facts[$entry.key]=$null -ne (Get-Service -Name $entry.name -ErrorAction SilentlyContinue)}catch{}
}
try{
    $packages=@(Get-AppxPackage -Name Claude -ErrorAction Stop|Where-Object {$_.Publisher -match 'Anthropic, PBC' -and $_.PackageFamilyName -ceq 'Claude_pzs8sxrjxfjjc'})
    $facts.officialMsixPresent=$packages.Count -gt 0
}catch{}
$report=Get-HongAiCoworkReadiness -Mode $Mode -Facts $facts
$json=$report|ConvertTo-Json -Depth 6
if($OutputPath){
    $absolute=[IO.Path]::GetFullPath($OutputPath)
    if([IO.Path]::GetFileName($absolute) -cne 'cowork-readiness.json'){throw 'OUTPUT_FILENAME_MUST_BE_COWORK_READINESS_JSON'}
    if(Test-Path -LiteralPath $absolute){$old=Get-Content -LiteralPath $absolute -Raw -Encoding UTF8|ConvertFrom-Json;if($old.schema -cne 'hongai.cowork-readiness.v1'){throw 'EXISTING_REPORT_NOT_OWNED_BY_THIS_TOOL'}}
    [IO.File]::WriteAllText($absolute,$json,[Text.UTF8Encoding]::new($false))
}
$json
