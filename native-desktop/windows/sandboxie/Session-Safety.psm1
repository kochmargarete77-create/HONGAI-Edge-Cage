Set-StrictMode -Version Latest
function Enter-HongAiSessionOwner {
    param([Parameter(Mandatory)][string]$DataRoot)
    $path=Join-Path $DataRoot 'session-owner.lock'
    if((Get-Item -LiteralPath $DataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'SESSION_DATA_LINK_REJECTED'}
    if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'SESSION_OWNER_LINK_REJECTED'}}
    try{return [IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{throw 'CAGE_SESSION_ALREADY_RUNNING_OR_OWNER_LOCK_UNAVAILABLE'}
}
function Write-HongAiSessionStatus {
    param([Parameter(Mandatory)][string]$DataRoot,[Parameter(Mandatory)]$Status)
    $path=Join-Path $DataRoot 'session-status.json';$pending=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($pending,($Status|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $path){[IO.File]::Replace($pending,$path,$path+'.previous')}else{[IO.File]::Move($pending,$path)}
}
function Get-HongAiEnvironmentIdentity {
    param([Parameter(Mandatory)][string]$DataRoot,[Parameter(Mandatory)][string]$OwnerSid)
    $path=Join-Path $DataRoot 'environment-identity.json'
    $sha=[Security.Cryptography.SHA256]::Create();try{$rootHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($DataRoot).TrimEnd('\').ToUpperInvariant()))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    if(Test-Path -LiteralPath $path){
        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'ENVIRONMENT_IDENTITY_LINK_REJECTED'}
        $identity=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
        $parsed=[guid]::Empty
        if($identity.schema -cne 'hongai.environment-identity.v1' -or $identity.ownerSid -cne $OwnerSid -or $identity.dataRootHash -cne $rootHash -or -not[guid]::TryParse([string]$identity.environmentId,[ref]$parsed)){throw 'ENVIRONMENT_IDENTITY_MIGRATION_REVIEW_REQUIRED_NO_RESET'}
    }else{
        $identity=[pscustomobject][ordered]@{schema='hongai.environment-identity.v1';environmentId=[guid]::NewGuid().ToString('D');ownerSid=$OwnerSid;dataRootHash=$rootHash;profileLayout='v1';createdUtc=[datetime]::UtcNow.ToString('o');hardwareIdentityVirtualized=$false}
        [IO.File]::WriteAllText($path,($identity|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    }
    return $identity.environmentId
}
Export-ModuleMember -Function Enter-HongAiSessionOwner,Write-HongAiSessionStatus,Get-HongAiEnvironmentIdentity
