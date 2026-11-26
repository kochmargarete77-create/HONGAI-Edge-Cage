[CmdletBinding()]
param([Parameter(Mandatory)][string]$EnginePath,[Parameter(Mandatory)][string]$BoxName,[Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][int]$ProxyPort)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows'){throw 'DISPOSABLE_GITHUB_CI_ONLY'}
$msix=Join-Path $Root 'Claude-official.msix'
Invoke-WebRequest -Uri 'https://downloads.claude.ai/releases/win32/x64/6.28899.6/Claude-2f5fc59b2d1c672dd9dced86720c50f48cca0cf9.msix' -OutFile $msix
if((Get-FileHash $msix -Algorithm SHA256).Hash -ine 'D95045A5354F2058FC380B5F1400AD3B66C841692644CB4C0C70CA3D4B6CCD5A'){throw 'OFFICIAL_MSIX_HASH_MISMATCH'}
$unpacked=Join-Path $Root 'official-unpacked'
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($msix,$unpacked)
$executable=Join-Path $unpacked 'app\Claude.exe'
$signature=Get-AuthenticodeSignature -LiteralPath $executable
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Anthropic'){throw 'OFFICIAL_EXECUTABLE_SIGNATURE_INVALID'}
$start=Join-Path $EnginePath 'Start.exe'
$policyReport=Join-Path $Root 'reports\official-policy.txt'
$policy='/box:'+$BoxName+' /silent /hide_window /wait "'+(Join-Path $Root 'fixture.exe')+'" policy '+$BoxName+' "'+$policyReport+'" "'+$Root+'" '+$ProxyPort
$p=Start-Process -FilePath $start -ArgumentList $policy -Wait -PassThru
if(-not(Test-Path $policyReport) -or [IO.File]::ReadAllText($policyReport) -cne "0|$BoxName"){throw 'VIRTUALIZED_POLICY_WRITE_FAILED'}
if(Test-Path 'HKCU:\SOFTWARE\Policies\Claude'){throw 'HOST_POLICY_WAS_MODIFIED_EXPECTED_VIRTUALIZATION'}
$profile=Join-Path $Root 'workspace\official-profile'
$report=[ordered]@{officialHashVerified=$true;officialSignature='Valid';outsidePolicyAbsent=$true;unpackedStart=$false;registeredStart=$false;loginAttempted=$false;customerAccepted=$false;processCount=0}
function Start-OwnedOfficial([string]$Path){
    Start-Sleep -Seconds 2
    $arguments='/box:'+$BoxName+' /silent /hide_window /env:HTTP_PROXY=http://127.0.0.1:'+$ProxyPort+' /env:HTTPS_PROXY=http://127.0.0.1:'+$ProxyPort+' "'+$Path+'" --user-data-dir="'+$profile+'" --proxy-server=http://127.0.0.1:'+$ProxyPort+' --proxy-bypass-list=<-loopback> --disable-quic --no-first-run'
    $null=Start-Process -FilePath $start -ArgumentList $arguments -PassThru
    Start-Sleep -Seconds 8
    @((Get-CimInstance Win32_Process -Filter "Name='Claude.exe'" -ErrorAction SilentlyContinue)|Where-Object {$_.ExecutablePath -ieq $Path -or $_.CommandLine -like ('*'+$profile+'*')})
}
try{
    $owned=@(Start-OwnedOfficial $executable)
    $report.unpackedStart=$owned.Count -gt 0
    if($owned.Count -eq 0){
        & $start ("/box:"+$BoxName) /terminate | Out-Null
        if(Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue){throw 'PREEXISTING_OFFICIAL_PACKAGE_NOT_OWNED'}
        Add-AppxPackage -Path $msix -ErrorAction Stop
        $package=Get-AppxPackage -Name Claude | Select-Object -First 1
        $executable=Join-Path $package.InstallLocation 'app\Claude.exe'
        $owned=@(Start-OwnedOfficial $executable)
        $report.registeredStart=$owned.Count -gt 0
    }
    $report.processCount=$owned.Count
    if($owned.Count -eq 0){throw 'OFFICIAL_DESKTOP_FAILED_INSIDE_SIGNED_SANDBOX'}
    $probeReport=Join-Path $Root 'reports\official-membership.txt'
    $probe='/box:'+$BoxName+' /silent /hide_window /wait "'+(Join-Path $Root 'fixture.exe')+'" probe-process '+$BoxName+' "'+$probeReport+'" "'+$Root+'" '+$owned[0].ProcessId
    Start-Sleep -Seconds 2
    $null=Start-Process -FilePath $start -ArgumentList $probe -Wait -PassThru
    if(-not(Test-Path $probeReport) -or [IO.File]::ReadAllText($probeReport) -cne "0|$BoxName"){throw 'OFFICIAL_KERNEL_BOX_MEMBERSHIP_FAILED'}
    $report.officialKernelBoxMembership='PASS'
    $report.offlineStart='PASS'
    Write-Host "PASS official signed Claude Desktop runs in signed sandbox; processes=$($owned.Count); login=false"
} catch {$report.error=$_.Exception.Message;throw}
finally{
    & $start ("/box:"+$BoxName) /terminate | Out-Null
    if($null -ne $package){Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue}
    $report|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Root 'official-desktop-status.json') -Encoding UTF8
}
