param([Parameter(Mandatory)][string]$TemporaryRoot)
$ErrorActionPreference='Stop'
$root=Join-Path $TemporaryRoot ('session-safety-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $root
Import-Module (Join-Path $PSScriptRoot 'Session-Safety.psm1') -Force
$receipt=@{schema='hongai.cage.installation.v1';dataRoot=$root;ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
[IO.File]::WriteAllText((Join-Path $root 'installation.json'),($receipt|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
Write-HongAiSessionStatus -DataRoot $root -Status @{phase='RUNNING';sessionId='owned-test-only'}
Write-HongAiSessionStatus -DataRoot $root -Status @{phase='RUNNING';sessionId='owned-test-only';atomicReplacementVerified=$true}
$before=(Get-FileHash (Join-Path $root 'session-status.json')).Hash
$lock=Enter-HongAiSessionOwner -DataRoot $root
try{
    $ps="$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $args='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'Run-Session.ps1')+'" -DataRoot "'+$root+'" -Workspace "'+$root+'" -StopFile "'+(Join-Path $root 'signals\test.stop')+'"'
    $p=Start-Process -FilePath $ps -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if($p.ExitCode -eq 0 -or (Get-FileHash (Join-Path $root 'session-status.json')).Hash -cne $before){throw 'DUPLICATE_SESSION_CHANGED_ACTIVE_STATUS'}
}finally{$lock.Dispose()}
$again=Enter-HongAiSessionOwner -DataRoot $root;$again.Dispose()
Write-Output 'PASS duplicate session cannot overwrite active status; owner lock releases without deleting state'
$id1=Get-HongAiEnvironmentIdentity -DataRoot $root -OwnerSid $receipt.ownerSid
$id2=Get-HongAiEnvironmentIdentity -DataRoot $root -OwnerSid $receipt.ownerSid
if($id1 -cne $id2){throw 'ENVIRONMENT_IDENTITY_CHANGED_ON_REUSE'}
Write-Output 'PASS local environment identity persists without spoofing hardware or modifying login data'
$logs=Join-Path $root 'Profile\logs';$null=New-Item -ItemType Directory -Path $logs -Force
[IO.File]::WriteAllText((Join-Path $logs 'main.log'),"HTTP/1.1 401 Unauthorized token=PRIVATE_CANARY_NEVER_EXPORT`nsafeStorage decrypt error PRIVATE_CANARY_NEVER_EXPORT`ncrash_reporter_started_ms: 429")
[IO.File]::WriteAllText((Join-Path $root 'Profile\Cookies'),'PRIVATE_CANARY_NEVER_EXPORT')
$json=& (Join-Path $PSScriptRoot 'Collect-AuthDiagnostics.ps1') -DataRoot $root
$diag=$json|ConvertFrom-Json
if($json.Contains('PRIVATE_CANARY_NEVER_EXPORT') -or $json.Contains($root) -or $diag.eventCounts.explicitHttp401 -ne 1 -or $diag.eventCounts.credentialStoreFailure -ne 1 -or $diag.credentialStoreContentsOpened -or $diag.credentialValuesExported){throw 'AUTH_DIAGNOSTIC_SCOPE_OR_REDACTION_FAILED'}
Write-Output 'PASS auth diagnostics export only event counts and storage metadata, no synthetic secrets or raw paths'
$compiler="$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$native=Split-Path $PSScriptRoot -Parent
& $compiler /nologo /target:exe /optimize+ ("/out:"+(Join-Path $root 'proxy-proof.exe')) (Join-Path $native 'SessionProxy.cs') (Join-Path $native 'Test-SessionProxy.cs')
if($LASTEXITCODE -ne 0){throw 'PROXY_PROOF_COMPILE_FAILED'}
& (Join-Path $root 'proxy-proof.exe')
if($LASTEXITCODE -ne 0){throw 'PROXY_PAUSE_RESUME_PROOF_FAILED'}
