Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-HongAiNativeEngine {
    $exe=Join-Path $PSScriptRoot 'resources\HONGAI-OfficialBoundary.exe'
    $manifest=Join-Path $PSScriptRoot 'resources\native-engine.json'
    if(-not(Test-Path -LiteralPath $exe -PathType Leaf)-or-not(Test-Path -LiteralPath $manifest -PathType Leaf)){throw 'NATIVE_ENGINE_MISSING'}
    $data=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json
    if($data.schema -cne 'hongai.native-engine.v1' -or (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $data.sha256){throw 'NATIVE_ENGINE_HASH_MISMATCH'}
    return $exe
}
function Get-HongAiNativeInventory {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $engine=Get-HongAiNativeEngine
    $result=& $engine --inventory $PackageRoot
    if($LASTEXITCODE -ne 0){throw 'NATIVE_OFFICIAL_INVENTORY_FAILED'}
    return @($result|ConvertFrom-Json)
}
function Invoke-HongAiNativeBoundary {
    param([Parameter(Mandatory)][ValidateSet('Install','Verify','Rollback')][string]$Operation,[int]$ProxyPort=0)
    $null=Get-HongAiNativeEngine
    if($Operation -eq 'Install' -and ($ProxyPort -lt 1024 -or $ProxyPort -gt 65535)){throw 'NATIVE_PROXY_PORT_INVALID'}
    $ticket=[guid]::NewGuid().ToString('N')
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $helper=Join-Path $PSScriptRoot 'Native-Boundary-Elevation.ps1'
    $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -Operation '+$Operation+' -OriginalUserSid '+$sid+' -Ticket '+$ticket+' -ProxyPort '+$ProxyPort
    $worker=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Hidden -PassThru -Wait
    $resultPath=Join-Path $PSScriptRoot ('.state\native-'+$Operation.ToLowerInvariant()+'.json')
    if(-not(Test-Path -LiteralPath $resultPath -PathType Leaf)){throw 'NATIVE_HELPER_NO_RESULT'}
    $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
    if($result.ticket -cne $ticket -or $worker.ExitCode -ne 0 -or -not $result.passed){throw 'NATIVE_HELPER_FAILED_REVIEW_RECOVERY_STATE'}
    return $result
}
Export-ModuleMember -Function Get-HongAiNativeEngine,Get-HongAiNativeInventory,Invoke-HongAiNativeBoundary
