[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$out=Join-Path $PSScriptRoot 'build'
$null=New-Item -ItemType Directory -Path $out -Force
$env:TEMP=$out;$env:TMP=$out
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /platform:x64 /target:exe /optimize+ /r:System.Web.Extensions.dll /main:HongAi.NativeBoundary.OfficialProgram ("/out:"+(Join-Path $out 'HONGAI-OfficialBoundary.exe')) (Join-Path $PSScriptRoot 'WfpBoundary.cs') (Join-Path $PSScriptRoot 'OfficialBoundary.cs')
if($LASTEXITCODE -ne 0){throw 'OFFICIAL_BOUNDARY_COMPILE_FAILED'}
$package=Get-AppxPackage -Name Claude | Where-Object Publisher -Match 'Anthropic, PBC' | Select-Object -First 1
if($package){
    $text=& (Join-Path $out 'HONGAI-OfficialBoundary.exe') --inventory $package.InstallLocation
    if($LASTEXITCODE -ne 0){throw 'OFFICIAL_INVENTORY_FAILED'}
    $inventory=$text|ConvertFrom-Json
    [pscustomobject]@{VerifiedOfficialExecutables=@($inventory).Count;Compiler='NET Framework x64';NetworkChanges=0}
}
