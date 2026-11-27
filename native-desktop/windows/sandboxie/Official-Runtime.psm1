Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-HongAiRuntimeHash([string]$Path){
    $sha=[Security.Cryptography.SHA256]::Create()
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{return (-join ($sha.ComputeHash($stream)|ForEach-Object {$_.ToString('x2')}))}finally{$stream.Dispose();$sha.Dispose()}
}

function Assert-HongAiRuntimeSignature([string]$Executable){
    $signature=Get-AuthenticodeSignature -LiteralPath $Executable
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Anthropic, PBC'){throw 'OFFICIAL_CLAUDE_SIGNATURE_INVALID'}
}

function Get-HongAiRuntimeFiles([string]$Root){
    $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($Root)
    $count=0;$bytes=0L
    while($queue.Count -gt 0){
        $directory=$queue.Dequeue()
        foreach($item in Get-ChildItem -LiteralPath $directory -Force){
            $count++;if($count -gt 20000){throw 'OFFICIAL_RUNTIME_ENTRY_BUDGET_EXCEEDED'}
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OFFICIAL_RUNTIME_CHILD_LINK_REJECTED'}
            if($item.PSIsContainer){$queue.Enqueue($item.FullName)}else{
                $bytes+=$item.Length;if($bytes -gt 2GB){throw 'OFFICIAL_RUNTIME_SIZE_BUDGET_EXCEEDED'}
                $item
            }
        }
    }
}

function Assert-HongAiCachedRuntime([string]$Target,[string]$PackageFullName){
    if((Get-Item -LiteralPath $Target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OFFICIAL_RUNTIME_CACHE_LINK_REJECTED'}
    $manifest=Get-Content -LiteralPath (Join-Path $Target 'runtime-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if($manifest.schema -cne 'hongai.official-runtime.v1' -or $manifest.packageFullName -cne $PackageFullName){throw 'OFFICIAL_RUNTIME_CACHE_IDENTITY_MISMATCH'}
    $actual=@(Get-HongAiRuntimeFiles (Join-Path $Target 'app'))
    if($actual.Count -ne @($manifest.files).Count){throw 'OFFICIAL_RUNTIME_CACHE_FILE_SET_CHANGED'}
    $seen=@{}
    foreach($entry in $manifest.files){
        $file=[IO.Path]::GetFullPath((Join-Path $Target ([string]$entry.path)))
        if(-not $file.StartsWith((Join-Path $Target 'app')+'\',[StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($file)){throw 'OFFICIAL_RUNTIME_MANIFEST_PATH_INVALID'}
        $seen[$file]=$true
        if((Get-HongAiRuntimeHash $file) -cne $entry.sha256){throw 'OFFICIAL_RUNTIME_CACHE_HASH_CHANGED'}
    }
    Assert-HongAiRuntimeSignature (Join-Path $Target 'app\Claude.exe')
    return $actual.Count
}

function Save-HongAiRuntimeState([string]$Cache,[string]$PackageFullName){
    $path=Join-Path $Cache 'runtime-state.json';$previous=$null
    if(Test-Path -LiteralPath $path){
        $old=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
        if($old.schema -cne 'hongai.runtime-state.v1'){throw 'OFFICIAL_RUNTIME_STATE_INVALID'}
        $previous=if($old.current -cne $PackageFullName){$old.current}else{$old.previous}
    }
    if($previous -and $previous -notmatch '^Claude_[0-9.]+_x64__pzs8sxrjxfjjc$'){throw 'OFFICIAL_RUNTIME_STATE_INVALID'}
    $state=[ordered]@{schema='hongai.runtime-state.v1';current=$PackageFullName;previous=$previous;policyRevision='private-gateway-v1';updatedUtc=[datetime]::UtcNow.ToString('o');automaticUnprotectedFallback=$false}
    $temporary=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($temporary,($state|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $path){[IO.File]::Replace($temporary,$path,$path+'.previous')}else{[IO.File]::Move($temporary,$path)}
}

function Remove-HongAiObsoleteRuntimes([string]$Cache,[string]$Keep){
    # Only complete, hash-verified, signed copies created by this product are
    # eligible. Never touch WindowsApps, the profile, workspaces or Recovery.
    $versions=@(Get-ChildItem -LiteralPath $Cache -Directory|Where-Object {$_.Name -match '^Claude_[0-9.]+_x64__pzs8sxrjxfjjc$'}|Sort-Object LastWriteTimeUtc -Descending)
    $retained=@($Keep)
    $statePath=Join-Path $Cache 'runtime-state.json'
    if(Test-Path -LiteralPath $statePath){$state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8|ConvertFrom-Json;if($state.schema -cne 'hongai.runtime-state.v1'){throw 'OFFICIAL_RUNTIME_STATE_INVALID'};if($state.current -cne $Keep){$retained+=$state.current}else{$retained+=$state.previous}}
    if($retained.Count -lt 2){$retained+=@($versions|Where-Object Name -CNE $Keep|Select-Object -First 1|ForEach-Object Name)}
    foreach($version in $versions){
        if($version.Name -in $retained){continue}
        $resolved=[IO.Path]::GetFullPath($version.FullName)
        if([IO.Path]::GetDirectoryName($resolved) -cne $Cache -or $resolved -cne $version.FullName){throw 'OFFICIAL_RUNTIME_CLEANUP_SCOPE_REJECTED'}
        $null=Assert-HongAiCachedRuntime $resolved $version.Name
        $running=@(Get-Process -ErrorAction SilentlyContinue|Where-Object {try{$_.Path -and $_.Path.StartsWith($resolved+'\',[StringComparison]::OrdinalIgnoreCase)}catch{$false}})
        if($running.Count){throw 'PREVIOUS_OFFICIAL_RUNTIME_STILL_RUNNING'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

function Get-HongAiPrivateOfficialRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)
    # The installed package remains registered, untouched and signed. Do not
    # activate its execution alias outside the process boundary. Instead run
    # a byte-identical private copy of the signed desktop payload in the box.
    $package=Get-AppxPackage -Name Claude | Where-Object {
        $_.Publisher -match 'Anthropic, PBC' -and $_.PackageFullName -match '^Claude_[0-9.]+_x64__pzs8sxrjxfjjc$'
    } | Sort-Object Version -Descending | Select-Object -First 1
    if(-not $package){throw 'SUPPORTED_OFFICIAL_CLAUDE_X64_MSIX_NOT_INSTALLED'}
    $source=[IO.Path]::GetFullPath((Join-Path $package.InstallLocation 'app')).TrimEnd('\')
    Assert-HongAiRuntimeSignature (Join-Path $source 'Claude.exe')
    $cache=Join-Path $DataRoot 'OfficialRuntime'
    $target=Join-Path $cache $package.PackageFullName
    $executable=Join-Path $target 'app\Claude.exe'
    $null=New-Item -ItemType Directory -Path $cache -Force
    if((Get-Item -LiteralPath $cache -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OFFICIAL_RUNTIME_CACHE_LINK_REJECTED'}
    if(Test-Path -LiteralPath $target){
        $count=Assert-HongAiCachedRuntime $target $package.PackageFullName
        Remove-HongAiObsoleteRuntimes $cache $package.PackageFullName
        Save-HongAiRuntimeState $cache $package.PackageFullName
        return [pscustomobject]@{Executable=$executable;SourceKind='MSIX_PRIVATE_SIGNED_COPY';PackageFullName=$package.PackageFullName;SourceRoot=$source;CacheReused=$true;FilesVerified=$count}
    }
    Remove-HongAiObsoleteRuntimes $cache $package.PackageFullName
    $files=@(Get-HongAiRuntimeFiles $source)
    $required=($files|Measure-Object -Property Length -Sum).Sum
    if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($DataRoot))).AvailableFreeSpace -lt ($required+1GB)){throw 'INSUFFICIENT_SPACE_FOR_PRIVATE_OFFICIAL_RUNTIME'}
    $stage=Join-Path $cache ('.stage-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path (Join-Path $stage 'app')
    $rows=[Collections.Generic.List[object]]::new()
    try{
        foreach($file in $files){
            $relative='app\'+$file.FullName.Substring($source.Length+1)
            $destination=Join-Path $stage $relative
            $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force
            # Streaming avoids inheriting package EFS/protected-file metadata,
            # and avoids reading a 250 MB executable into a single byte array.
            $reader=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $writer=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $sha=[Security.Cryptography.SHA256]::Create()
            $crypto=[Security.Cryptography.CryptoStream]::new($writer,$sha,[Security.Cryptography.CryptoStreamMode]::Write)
            try{$reader.CopyTo($crypto,262144);$crypto.FlushFinalBlock();$hash=-join ($sha.Hash|ForEach-Object {$_.ToString('x2')})}finally{$reader.Dispose();$crypto.Dispose();$writer.Dispose();$sha.Dispose()}
            if((Get-HongAiRuntimeHash $destination) -cne $hash){throw 'OFFICIAL_RUNTIME_COPY_HASH_MISMATCH'}
            $rows.Add([ordered]@{path=$relative;bytes=$file.Length;sha256=$hash})
        }
        Assert-HongAiRuntimeSignature (Join-Path $stage 'app\Claude.exe')
        $current=Get-AppxPackage -Name Claude | Where-Object PackageFullName -EQ $package.PackageFullName | Select-Object -First 1
        if(-not $current -or $current.InstallLocation -cne $package.InstallLocation){throw 'OFFICIAL_PACKAGE_CHANGED_DURING_COPY'}
        $manifest=[ordered]@{schema='hongai.official-runtime.v1';packageFullName=$package.PackageFullName;sourceKind='REGISTERED_MSIX';officialFilesModified=$false;packageIdentityRetained=$false;files=$rows.ToArray()}
        [IO.File]::WriteAllText((Join-Path $stage 'runtime-manifest.json'),($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $stage -Destination $target
    }catch{
        # Retain failed copies for review/recovery; never delete package files
        # or change WindowsApps ownership/ACL to make a launch succeed.
        throw ('OFFICIAL_RUNTIME_PREPARATION_FAILED: '+$_.Exception.Message)
    }
    Save-HongAiRuntimeState $cache $package.PackageFullName
    [pscustomobject]@{Executable=$executable;SourceKind='MSIX_PRIVATE_SIGNED_COPY';PackageFullName=$package.PackageFullName;SourceRoot=$source;CacheReused=$false;FilesVerified=$files.Count}
}

Export-ModuleMember -Function Get-HongAiPrivateOfficialRuntime
