[CmdletBinding()]
param([Parameter(Mandatory)][string]$RuntimeSource,[string]$BuildTag='0.2.0-pilot.1')
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$out=Join-Path (Split-Path $root) ('release-'+$BuildTag)
if(Test-Path $out){throw 'BUILD_TAG_ALREADY_EXISTS'}
$stage=Join-Path $out 'staging'
$payload=Join-Path $stage 'payload'
$null=New-Item -ItemType Directory -Path $payload -Force
$source=(Resolve-Path -LiteralPath $RuntimeSource).Path
Get-ChildItem $source -Recurse -File|Where-Object {
    $_.FullName -notmatch '[\\/]\.(tmp|state)[\\/]' -and $_.Name -notin @('clash-handoff.json','04-本机刷新交接-仅本机.cmd','CHECKSUMS-SHA256.txt')
}|ForEach-Object {
    $relative=$_.FullName.Substring($source.Length+1);$dest=Join-Path $payload $relative
    $null=New-Item -ItemType Directory -Path (Split-Path $dest) -Force
    Copy-Item -LiteralPath $_.FullName -Destination $dest
}
Get-ChildItem $payload -Recurse -File|Where-Object {$_.Extension -in '.ps1','.psm1'}|ForEach-Object {
    $text=[IO.File]::ReadAllText($_.FullName,[Text.Encoding]::UTF8);[IO.File]::WriteAllText($_.FullName,$text,[Text.UTF8Encoding]::new($true))
}
$installer=Join-Path $stage 'Install-DesktopGuard.ps1'
$text=[IO.File]::ReadAllText((Join-Path $root 'Install-DesktopGuard.ps1'),[Text.Encoding]::UTF8)
[IO.File]::WriteAllText($installer,$text,[Text.UTF8Encoding]::new($true))
$lines=Get-ChildItem $payload -Recurse -File|Sort-Object FullName|ForEach-Object {
    (Get-FileHash $_.FullName -Algorithm SHA256).Hash+'  '+$_.FullName.Substring($payload.Length+1).Replace('\','/')
}
[IO.File]::WriteAllLines((Join-Path $payload 'CHECKSUMS-SHA256.txt'),$lines,[Text.UTF8Encoding]::new($false))
$archive=Join-Path $out 'installer-payload.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
$hash=Join-Path $out 'installer-payload.sha256'
[IO.File]::WriteAllText($hash,(Get-FileHash $archive -Algorithm SHA256).Hash,[Text.UTF8Encoding]::new($false))
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$setup=Join-Path $out ('HONGAI-CAGE-DesktopGuard-'+$BuildTag+'-Windows-x64-Setup.exe')
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /r:System.Windows.Forms.dll /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll ("/resource:"+$archive+',hongai.payload') ("/resource:"+$hash+',hongai.payload.sha256') ("/out:"+$setup) (Join-Path $root 'Setup.cs')
if($LASTEXITCODE -ne 0){throw 'ONECLICK_SETUP_COMPILE_FAILED'}
$setupHash=(Get-FileHash $setup -Algorithm SHA256).Hash
[IO.File]::WriteAllText($setup+'.sha256',$setupHash+'  '+[IO.Path]::GetFileName($setup)+"`n",[Text.UTF8Encoding]::new($false))
[pscustomobject]@{Setup=$setup;Bytes=(Get-Item $setup).Length;SHA256=$setupHash;PayloadFiles=$lines.Count;Signed=$false;CustomerAccepted=$false}
