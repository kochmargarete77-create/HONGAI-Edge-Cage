[CmdletBinding()]
param([Parameter(Mandatory)][string]$DataRoot,[string]$OutputPath)
$ErrorActionPreference='Stop'
$DataRoot=[IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
$receipt=Get-Content -LiteralPath (Join-Path $DataRoot 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($receipt.schema -cne 'hongai.cage.installation.v1' -or $receipt.dataRoot -cne $DataRoot -or $receipt.ownerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'DIAGNOSTIC_OWNER_MISMATCH'}
$patterns=[ordered]@{
    explicitHttp401='(?i)(?:HTTP/\S+\s+401\b|(?:status|statusCode)\s*[=:]\s*401\b|401\s+Unauthorized)'
    explicitHttp403='(?i)(?:HTTP/\S+\s+403\b|(?:status|statusCode)\s*[=:]\s*403\b|403\s+Forbidden)'
    refreshFailure='(?i)(?:refresh.*(?:fail|error|invalid|denied)|(?:fail|error|invalid|denied).*refresh|invalid_grant)'
    credentialStoreFailure='(?i)(?:safeStorage|DPAPI|os_crypt|keychain).*(?:fail|error|denied|unavailable|decrypt)'
    persistenceFailure='(?i)(?:SQLITE_(?:IOERR|CORRUPT|FULL)|database is locked|(?:cookie|storage|profile).*(?:EACCES|access denied|permission denied|read.only))'
    identityOrCallbackEvents='(?i)(?:identity changed mid.flow|(?:oauth|callback).*(?:fail|error|mismatch|denied))'
    explicitAccountRestriction='(?i)(?:account (?:is )?(?:disabled|suspended|deactivated)|organization.*(?:on hold|suspended))'
}
$counts=[ordered]@{};foreach($key in $patterns.Keys){$counts[$key]=0}
$metadata=[Collections.Generic.List[object]]::new();$logs=0;$inspected=0;$queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($DataRoot)
while($queue.Count -gt 0 -and $inspected -lt 6000){
    $dir=$queue.Dequeue()
    foreach($item in Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue){
        $inspected++;if($inspected -gt 6000){break};if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
        if($item.PSIsContainer){if($item.FullName -notlike '*\OfficialRuntime*' -and $item.FullName -notlike '*\Recovery*' -and $item.FullName -notlike '*\Cache*' -and $queue.Count -lt 1000){$queue.Enqueue($item.FullName)};continue}
        if($item.Name -in @('Cookies','Local State','Preferences','Cookies-journal')){$metadata.Add([ordered]@{kind=$item.Name;bytes=$item.Length;modifiedUtc=$item.LastWriteTimeUtc.ToString('o')})}
        if($item.Name -notin @('main.log','claude.ai-web.log','remote-control.log') -or $logs -ge 12){continue}
        $logs++;$stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try{$take=[int][Math]::Min(1048576,$stream.Length);$null=$stream.Seek(-$take,[IO.SeekOrigin]::End);$buffer=New-Object byte[] $take;$read=$stream.Read($buffer,0,$take);$text=[Text.Encoding]::UTF8.GetString($buffer,0,$read);foreach($line in ($text -split "`n")){foreach($key in $patterns.Keys){if($line -match $patterns[$key]){$counts[$key]++}}}}finally{$stream.Dispose()}
    }
}
$state='NOT_OBSERVED';$statusFile=Join-Path $DataRoot 'session-status.json';if(Test-Path -LiteralPath $statusFile){try{$s=Get-Content -LiteralPath $statusFile -Raw -Encoding UTF8|ConvertFrom-Json;if($s.phase -in @('PREPARING','RUNNING','NETWORK_PAUSED','STOPPED','BLOCKED')){$state=$s.phase}}catch{}}
$report=[ordered]@{schema='hongai.auth-diagnostics.v1';platform='Windows';generatedUtc=[datetime]::UtcNow.ToString('o');sessionPhase=$state;storageMetadata=$metadata.ToArray();eventCounts=$counts;logTailsInspected=$logs;boundedEntryCount=$inspected;coverageComplete=$queue.Count -eq 0 -and $inspected -lt 6000;accountRestrictionConfirmed=$false;credentialStoreContentsOpened=$false;credentialValuesExported=$false;applicationLogTailsInspectedLocally=$true;rawLogExported=$false;loginStateChanged=$false;hostNetworkSettingsChanged=$false;scope='COUNTS_AND_STORAGE_METADATA_ONLY_NOT_ACCOUNT_OR_SESSION_ACCEPTANCE'}
$json=$report|ConvertTo-Json -Depth 6
if($OutputPath){$absolute=[IO.Path]::GetFullPath($OutputPath);if([IO.Path]::GetFileName($absolute) -cne 'auth-diagnostics.json' -or (Test-Path -LiteralPath $absolute)){throw 'OUTPUT_MUST_BE_NEW_AUTH_DIAGNOSTICS_JSON'};[IO.File]::WriteAllText($absolute,$json,[Text.UTF8Encoding]::new($false))}
$json
