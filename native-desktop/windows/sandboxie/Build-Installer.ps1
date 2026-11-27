[CmdletBinding()]
param([string]$LegacyRuntime,[Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference='Stop'
if(Test-Path $Destination){throw 'INSTALLER_BUILD_DESTINATION_EXISTS'}
$stage=Join-Path $Destination 'staging';$null=New-Item -ItemType Directory -Path $stage -Force
$env:TEMP=Join-Path $Destination '.tmp';$env:TMP=$env:TEMP;$null=New-Item -ItemType Directory -Path $env:TEMP -Force
$runtime=Join-Path $stage 'payload'
& (Join-Path $PSScriptRoot 'Build-Runtime.ps1') -LegacyRuntime $LegacyRuntime -Destination $runtime|Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-Cage.ps1') -Destination $runtime
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-Cage.ps1') -Destination $stage
$vendor=Join-Path $stage 'vendor';$null=New-Item -ItemType Directory -Path $vendor
$installer=Join-Path $vendor 'Sandboxie-Classic-x64-v5.74.1.exe'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sandboxie-plus/Sandboxie/releases/download/v1.19.1/Sandboxie-Classic-x64-v5.74.1.exe' -OutFile $installer
if((Get-FileHash $installer).Hash -ine '4F97400854B7B984DEDC5BD057B9F6886EB13A2CC29ED38B0094EBBE5483D57E'){throw 'CLASSIC_COMPONENT_HASH_MISMATCH'}
if((Get-AuthenticodeSignature $installer).Status -ne 'Valid'){throw 'CLASSIC_COMPONENT_SIGNATURE_INVALID'}
$licenses=Join-Path $runtime 'licenses';$null=New-Item -ItemType Directory -Path $licenses
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'licenses\Sandboxie-Classic-LICENSE.txt'),(Join-Path $PSScriptRoot 'licenses\GPL-3.0.txt') -Destination $licenses
$sourceOffer=@('Sandboxie Classic v5.74.1 / source tag v1.19.1','Original unmodified signed installer. License: GPLv3 or later.','Corresponding component source: https://github.com/sandboxie-plus/Sandboxie/tree/v1.19.1','Source archive: https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/v1.19.1.zip','HONG AI adapter source: https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/tree/native-desktop-development/native-desktop/windows','Brand assets remain identified as HONG AI; upstream component identity and notices are preserved.')
[IO.File]::WriteAllLines((Join-Path $licenses 'SOURCE-AND-NOTICES.txt'),$sourceOffer,[Text.UTF8Encoding]::new($false))
Get-ChildItem -LiteralPath $stage -File -Recurse|Where-Object {$_.Extension -in '.ps1','.psm1'}|ForEach-Object {$content=[IO.File]::ReadAllText($_.FullName);[IO.File]::WriteAllText($_.FullName,$content,[Text.UTF8Encoding]::new($true))}
$hashes=Get-ChildItem -LiteralPath $stage -File -Recurse|Where-Object {$_.FullName -notmatch '\\\.tmp\\'}|Sort-Object FullName|ForEach-Object {(Get-FileHash $_.FullName).Hash+'  '+$_.FullName.Substring($stage.Length+1).Replace('\','/')}
[IO.File]::WriteAllLines((Join-Path $stage 'CHECKSUMS-SHA256.txt'),$hashes,[Text.UTF8Encoding]::new($false))
$zip=Join-Path $Destination 'payload.zip';Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$hashFile=Join-Path $Destination 'payload.sha256';[IO.File]::WriteAllText($hashFile,(Get-FileHash $zip).Hash,[Text.UTF8Encoding]::new($false))
$setup=Join-Path $Destination 'HONGAI-CAGE-Desktop-0.3.0-pilot.3-Windows-x64-Setup.exe'
$compiler="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $compiler /nologo /platform:x64 /target:winexe /optimize+ /r:System.Windows.Forms.dll /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll ("/resource:"+$zip+',cage.payload') ("/resource:"+$hashFile+',cage.hash') ("/out:"+$setup) (Join-Path $PSScriptRoot 'CageSetup.cs')
if($LASTEXITCODE -ne 0){throw 'CAGE_INSTALLER_COMPILE_FAILED'}
$manifest=[ordered]@{product='HONG AI CAGE Desktop';version='0.3.0-pilot.3';sha256=(Get-FileHash $setup).Hash;bytes=(Get-Item $setup).Length;thirdParty='unmodified signed Sandboxie Classic core, GPLv3';customerAccepted=$false;loginAcceptance='NOT_RUN';coworkEnabled=$false;globalNetworkChanges=0}
[IO.File]::WriteAllText($setup+'.json',($manifest|ConvertTo-Json),[Text.UTF8Encoding]::new($false));$manifest|ConvertTo-Json
