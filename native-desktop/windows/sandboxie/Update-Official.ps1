[CmdletBinding()]
param([Parameter(Mandatory)][string]$ResultPath,[Parameter(Mandatory)][string]$OriginalUserSid,[Parameter(Mandatory)][string]$TemporaryDirectory)
$ErrorActionPreference='Stop'
$result=[ordered]@{updated=$false;hostNetworkSettingsChanged=$false;rebootPerformed=$false}
try{
    $env:TEMP=$TemporaryDirectory;$env:TMP=$env:TEMP
    $package=& (Join-Path $PSScriptRoot 'Ensure-Official.ps1') -OriginalUserSid $OriginalUserSid -RequireCatalogVersion
    $result.updated=$true;$result.version=[string]$package.Version
}catch{$result.error=$_.Exception.Message}
finally{[IO.File]::WriteAllText($ResultPath,($result|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
if(-not $result.updated){exit 1}
