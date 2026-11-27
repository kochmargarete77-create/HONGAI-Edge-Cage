[CmdletBinding()]
param([string]$OriginalUserSid,[string]$OfflinePackage,[switch]$RequireCatalogVersion)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(-not $OriginalUserSid){$OriginalUserSid=$currentSid}
$catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Official-Catalog.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($catalog.schema -cne 'hongai.official-catalog.v1'){throw 'OFFICIAL_CATALOG_INVALID'}
$release=[pscustomobject]@{version=[string]$catalog.windowsX64.version;url=[string]$catalog.windowsX64.url;sha256=[string]$catalog.windowsX64.sha256}
$lookupVerified=$false
if($RequireCatalogVersion -and -not $OfflinePackage){
    try{
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $request=[Net.HttpWebRequest]::Create('https://claude.ai/api/desktop/win32/x64/msix/latest/redirect')
        $request.AllowAutoRedirect=$false;$request.Method='GET';$request.Timeout=15000
        $response=$request.GetResponse()
        try{
            $location=[uri]$response.Headers['Location']
            if([int]$response.StatusCode -notin @(301,302,303,307,308) -or $location.Scheme -cne 'https' -or $location.Host -cne 'downloads.claude.ai' -or $location.UserInfo -or $location.Query -or $location.AbsolutePath -notmatch '^/releases/win32/x64/([0-9]+(?:\.[0-9]+){2,3})/Claude-[a-f0-9]+\.msix$'){throw 'OFFICIAL_UPDATE_REDIRECT_REJECTED'}
            $version=$matches[1]
            if([version]$version -lt [version]$release.version){throw 'OFFICIAL_UPDATE_DOWNGRADE_REJECTED'}
            if($version -cne $release.version){$release=[pscustomobject]@{version=$version;url=$location.AbsoluteUri;sha256=$null}}
            $lookupVerified=$true
        }finally{$response.Close()}
    }catch{Write-Verbose ('Official update check unavailable; using the verified release catalog: '+$_.Exception.Message)}
}
$package=Get-AppxPackage -User $OriginalUserSid -Name Claude|Where-Object {$_.Publisher -match 'Anthropic, PBC' -and $_.PackageFullName -match '^Claude_[0-9.]+_x64__pzs8sxrjxfjjc$'}|Sort-Object Version -Descending|Select-Object -First 1
if($package -and ([version]$package.Version -ge [version]$release.version -or -not $RequireCatalogVersion)){return $package}
# Register in the real customer identity, never accidentally in an alternate
# administrator's account. No remove/reset/repair of an existing package.
if($currentSid -cne $OriginalUserSid){throw 'OFFICIAL_INSTALL_REQUIRES_ORIGINAL_USER_CONTEXT'}
if(@(Get-Process Claude -ErrorAction SilentlyContinue).Count){throw 'EXIT_CLAUDE_BEFORE_OFFICIAL_UPDATE'}
$destination=Join-Path $env:TEMP 'HONGAI-Official-Download'
$null=New-Item -ItemType Directory -Path $destination -Force
if((Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OFFICIAL_DOWNLOAD_LINK_REJECTED'}
$file=Join-Path $destination ('Claude-'+$release.version+'.msix')
if($OfflinePackage){$file=[IO.Path]::GetFullPath($OfflinePackage)}else{
    if(-not(Test-Path -LiteralPath $file) -or -not $release.sha256 -or (Get-FileHash -LiteralPath $file).Hash -ine $release.sha256){
        $uri=[uri]$release.url
        if($uri.Scheme -cne 'https' -or $uri.Host -cne 'downloads.claude.ai'){throw 'OFFICIAL_DOWNLOAD_SOURCE_REJECTED'}
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $download=[Net.HttpWebRequest]::Create($uri);$download.AllowAutoRedirect=$false;$download.Timeout=180000;$download.ReadWriteTimeout=30000
        $response=$download.GetResponse()
        try{
            if([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt 1GB){throw 'OFFICIAL_PACKAGE_DOWNLOAD_REJECTED'}
            $reader=$response.GetResponseStream();$writer=[IO.File]::Open($file,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{
                $buffer=New-Object byte[] 262144;$total=0L;$started=[datetime]::UtcNow
                while(($read=$reader.Read($buffer,0,$buffer.Length)) -gt 0){$total+=$read;if($total -gt 1GB -or ([datetime]::UtcNow-$started).TotalSeconds -gt 180){throw 'OFFICIAL_PACKAGE_DOWNLOAD_BUDGET_EXCEEDED'};$writer.Write($buffer,0,$read)}
            }finally{$reader.Dispose();$writer.Dispose()}
        }finally{$response.Close()}
    }
}
if((Get-Item -LiteralPath $file).Length -gt 1GB){throw 'OFFICIAL_PACKAGE_DOWNLOAD_BUDGET_EXCEEDED'}
if($release.sha256 -and (Get-FileHash -LiteralPath $file).Hash -ine $release.sha256){throw 'OFFICIAL_MSIX_HASH_MISMATCH'}
$signature=Get-AuthenticodeSignature -LiteralPath $file
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Anthropic, PBC'){throw 'OFFICIAL_MSIX_SIGNATURE_INVALID'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead($file)
try{
    $entry=$archive.GetEntry('AppxManifest.xml');if(-not $entry -or $entry.Length -gt 1MB){throw 'OFFICIAL_PACKAGE_MANIFEST_INVALID'}
    $stream=$entry.Open();$reader=[IO.StreamReader]::new($stream)
    try{[xml]$manifest=$reader.ReadToEnd()}finally{$reader.Dispose();$stream.Dispose()}
    $identity=$manifest.Package.Identity
    $expected=([version]$release.version).ToString(3)+'.'+$(if(([version]$release.version).Revision -lt 0){'0'}else{([version]$release.version).Revision})
    if($identity.Name -cne 'Claude' -or $identity.ProcessorArchitecture -cne 'x64' -or $identity.Publisher -notmatch 'Anthropic, PBC' -or [version]$identity.Version -ne [version]$expected){throw 'OFFICIAL_PACKAGE_IDENTITY_MISMATCH'}
}finally{$archive.Dispose()}
Add-AppxPackage -Path $file -ErrorAction Stop
$installed=Get-AppxPackage -Name Claude|Where-Object {$_.PackageFamilyName -ceq $catalog.windowsX64.family -and [version]$_.Version -ge [version]$release.version}|Sort-Object Version -Descending|Select-Object -First 1
if(-not $installed){throw 'OFFICIAL_REGISTRATION_NOT_CONFIRMED'}
$installed
