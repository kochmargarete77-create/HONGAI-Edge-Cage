[CmdletBinding()]
param([string]$OriginalUserSid,[string]$OfflinePackage,[switch]$RequireCatalogVersion)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(-not $OriginalUserSid){$OriginalUserSid=$currentSid}
$catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Official-Catalog.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($catalog.schema -cne 'hongai.official-catalog.v1'){throw 'OFFICIAL_CATALOG_INVALID'}
$package=Get-AppxPackage -User $OriginalUserSid -Name Claude|Where-Object {$_.Publisher -match 'Anthropic, PBC' -and $_.PackageFullName -match '^Claude_[0-9.]+_x64__pzs8sxrjxfjjc$'}|Sort-Object Version -Descending|Select-Object -First 1
if($package -and ([version]$package.Version -ge [version]$catalog.windowsX64.version -or -not $RequireCatalogVersion)){return $package}
# Register in the real customer identity, never accidentally in an alternate
# administrator's account. No remove/reset/repair of an existing package.
if($currentSid -cne $OriginalUserSid){throw 'OFFICIAL_INSTALL_REQUIRES_ORIGINAL_USER_CONTEXT'}
if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count){throw 'EXIT_CLAUDE_BEFORE_OFFICIAL_UPDATE'}
$destination=Join-Path $env:TEMP 'HONGAI-Official-Download'
$null=New-Item -ItemType Directory -Path $destination -Force
if((Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OFFICIAL_DOWNLOAD_LINK_REJECTED'}
$file=Join-Path $destination 'Claude.msix'
if($OfflinePackage){$file=[IO.Path]::GetFullPath($OfflinePackage)}else{
    if(-not(Test-Path -LiteralPath $file) -or (Get-FileHash -LiteralPath $file).Hash -ine $catalog.windowsX64.sha256){
        $uri=[uri]$catalog.windowsX64.url
        if($uri.Scheme -cne 'https' -or $uri.Host -cne 'downloads.claude.ai'){throw 'OFFICIAL_DOWNLOAD_SOURCE_REJECTED'}
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $file -TimeoutSec 180 -MaximumRedirection 0
    }
}
if((Get-FileHash -LiteralPath $file).Hash -ine $catalog.windowsX64.sha256){throw 'OFFICIAL_MSIX_HASH_MISMATCH'}
$signature=Get-AuthenticodeSignature -LiteralPath $file
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Anthropic, PBC'){throw 'OFFICIAL_MSIX_SIGNATURE_INVALID'}
Add-AppxPackage -Path $file -ErrorAction Stop
$installed=Get-AppxPackage -Name Claude|Where-Object {$_.PackageFamilyName -ceq $catalog.windowsX64.family -and [version]$_.Version -ge [version]$catalog.windowsX64.version}|Sort-Object Version -Descending|Select-Object -First 1
if(-not $installed){throw 'OFFICIAL_REGISTRATION_NOT_CONFIRMED'}
$installed
