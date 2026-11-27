[CmdletBinding()]
param([string]$LegacyRuntime,[string]$Destination)
$ErrorActionPreference='Stop'
$native=Split-Path $PSScriptRoot -Parent
if(-not $LegacyRuntime){$LegacyRuntime=Join-Path $native 'runtime'}
if(-not $Destination){$Destination=Join-Path $PSScriptRoot 'build-runtime'}
if(Test-Path $Destination){throw 'RUNTIME_BUILD_DESTINATION_EXISTS'}
$null=New-Item -ItemType Directory -Path (Join-Path $Destination 'resources') -Force
$env:TEMP=Join-Path $Destination '.tmp';$env:TMP=$env:TEMP;$null=New-Item -ItemType Directory -Path $env:TEMP -Force
foreach($file in @('HONGAI.DesktopGuard.psm1','Managed-Claude-Policy.psm1','Native-Boundary-Bridge.psm1','New-HONGAI-Local-Handoff.ps1')){Copy-Item -LiteralPath (Join-Path $LegacyRuntime $file) -Destination $Destination}
foreach($file in @('Run-Session.ps1','Cage-UI.ps1','Official-Runtime.psm1','Ensure-Official.ps1','Update-Official.ps1','Official-Catalog.json','Test-Compatibility.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $Destination}
$compiler="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $compiler /nologo /platform:x64 /target:exe /optimize+ /r:System.Web.Extensions.dll /main:HongAi.NativeBoundary.OfficialProgram ("/out:"+(Join-Path $Destination 'resources\HONGAI-OfficialBoundary.exe')) (Join-Path $native 'WfpBoundary.cs') (Join-Path $native 'OfficialBoundary.cs')
if($LASTEXITCODE -ne 0){throw 'INVENTORY_HELPER_COMPILE_FAILED'}
& $compiler /nologo /platform:x64 /target:library /optimize+ ("/out:"+(Join-Path $Destination 'resources\HONGAI-SessionProxy.dll')) (Join-Path $native 'SessionProxy.cs')
if($LASTEXITCODE -ne 0){throw 'SESSION_GATEWAY_COMPILE_FAILED'}
& $compiler /nologo /platform:x64 /target:exe /optimize+ ("/out:"+(Join-Path $Destination 'resources\HONGAI-SessionControl.exe')) (Join-Path $PSScriptRoot 'SessionControl.cs')
if($LASTEXITCODE -ne 0){throw 'SESSION_CONTROL_COMPILE_FAILED'}
& $compiler /nologo /platform:x64 /target:winexe /optimize+ /r:System.Windows.Forms.dll ("/out:"+(Join-Path $Destination 'HONGAI-CAGE.exe')) (Join-Path $PSScriptRoot 'CageLauncher.cs')
if($LASTEXITCODE -ne 0){throw 'NATIVE_GUI_LAUNCHER_COMPILE_FAILED'}
$engine=[ordered]@{schema='hongai.native-engine.v1';sha256=(Get-FileHash (Join-Path $Destination 'resources\HONGAI-OfficialBoundary.exe')).Hash;scope='read-only official inventory helper in sandbox backend';customerAccepted=$false}
[IO.File]::WriteAllText((Join-Path $Destination 'resources\native-engine.json'),($engine|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
Get-ChildItem -LiteralPath $Destination -File -Recurse|Where-Object {$_.Extension -in '.ps1','.psm1'}|ForEach-Object {$content=[IO.File]::ReadAllText($_.FullName);[IO.File]::WriteAllText($_.FullName,$content,[Text.UTF8Encoding]::new($true))}
Write-Output $Destination
