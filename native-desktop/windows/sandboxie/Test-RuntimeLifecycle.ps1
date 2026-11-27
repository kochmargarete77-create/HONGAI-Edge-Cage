[CmdletBinding()]
param([Parameter(Mandatory)][string]$TemporaryRoot)
$ErrorActionPreference='Stop'
$root=Join-Path $TemporaryRoot ('runtime-lifecycle-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
Import-Module (Join-Path $PSScriptRoot 'Official-Runtime.psm1') -Force
$module=Get-Module 'Official-Runtime'
# Synthetic provider stays in this module/test process. Real signature and
# MSIX launch checks run separately on disposable Windows CI hosts.
& $module {
    param($testRoot)
    $script:testRoot=$testRoot;$script:testVersion=1
    function script:Assert-HongAiRuntimeSignature([string]$Executable){if(-not(Test-Path -LiteralPath $Executable)){throw 'TEST_EXECUTABLE_MISSING'}}
    function script:Get-AppxPackage {
        [CmdletBinding()]param([string]$Name)
        [pscustomobject]@{Publisher='CN=Anthropic, PBC';PackageFullName=('Claude_1.0.0.'+$script:testVersion+'_x64__pzs8sxrjxfjjc');Version=[version]('1.0.0.'+$script:testVersion);InstallLocation=(Join-Path $script:testRoot ('source-'+$script:testVersion))}
    }
} $root
foreach($version in 1..4){
    $app=Join-Path $root ('source-'+$version+'\app');$null=New-Item -ItemType Directory -Path $app
    [IO.File]::WriteAllText((Join-Path $app 'Claude.exe'),('test signed payload '+$version))
    & $module {param($version)$script:testVersion=$version} $version
    $result=Get-HongAiPrivateOfficialRuntime -DataRoot $root
    if($result.CacheReused -or $result.PackageFullName -cne ('Claude_1.0.0.'+$version+'_x64__pzs8sxrjxfjjc')){throw 'NEW_VERSION_NOT_PREPARED'}
    $again=Get-HongAiPrivateOfficialRuntime -DataRoot $root
    if(-not $again.CacheReused){throw 'VERIFIED_CACHE_NOT_REUSED'}
    $versions=@(Get-ChildItem (Join-Path $root 'OfficialRuntime') -Directory|Where-Object Name -Like 'Claude_*')
    if($versions.Count -gt 2){throw 'VERSION_ROTATION_NOT_BOUNDED'}
}
$latest=$result.Executable
[IO.File]::AppendAllText($latest,'tamper')
$blocked=$false
try{$null=Get-HongAiPrivateOfficialRuntime -DataRoot $root}catch{if($_.Exception.Message -like '*HASH_CHANGED*'){$blocked=$true}else{throw}}
if(-not $blocked){throw 'TAMPERED_CACHE_WAS_ACCEPTED'}
if(-not(Test-Path (Join-Path $root 'OfficialRuntime\Claude_1.0.0.3_x64__pzs8sxrjxfjjc\app\Claude.exe'))){throw 'PREVIOUS_COMPLETE_RUNTIME_WAS_LOST'}
$state=Get-Content (Join-Path $root 'OfficialRuntime\runtime-state.json') -Raw|ConvertFrom-Json
if($state.current -cne 'Claude_1.0.0.4_x64__pzs8sxrjxfjjc' -or $state.previous -cne 'Claude_1.0.0.3_x64__pzs8sxrjxfjjc' -or $state.automaticUnprotectedFallback){throw 'UPDATE_STATE_OR_FALLBACK_POLICY_INVALID'}
Write-Output 'PASS four successive updates, bounded cache, verified reuse, tamper refusal, previous version retained, no unprotected fallback'
